#!/usr/bin/env python3
"""
app.py — Slack interactivity webhook for Aditor Dispatch
Deployed on Railway at: https://aditor-dispatch-webhook.up.railway.app (set after first deploy)

Purpose:
  Receives Slack button click payloads (Accept / Decline from dispatch messages).
  Immediately ACKs with 200, gives visual feedback, and posts a DISPATCH_ACTION
  message to the automations channel so the Mac Mini heartbeat can pick it up.

Interactivity URL (set in Slack App settings):
  https://<RAILWAY_URL>/slack/actions

Environment variables (set in Railway dashboard):
  SLACK_BOT_TOKEN       <set in Railway dashboard>
  SLACK_SIGNING_SECRET  <from api.slack.com/apps -> Basic Information -> Signing Secret>
  DISPATCH_CHANNEL      C07UL6BAG1Z  (automations channel — or create #dispatch-actions)
"""

import hmac
import hashlib
import time
import uuid
import json
import os
import requests
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

# ── CONFIG (via environment variables) ────────────────────────────────────────

SLACK_BOT_TOKEN      = os.environ.get("SLACK_BOT_TOKEN", "")
SLACK_SIGNING_SECRET = os.environ.get("SLACK_SIGNING_SECRET", "")

# Filesystem inbox shared with the dispatch-agent on the same host.
# Webhook writes JSON files here; the agent's poller reads + deletes them.
# Replaces the legacy Slack-channel message bus.
ACTION_INBOX_DIR = os.environ.get("ACTION_INBOX_DIR", "/opt/dispatch-agent/action_inbox")

# Shared secret guarding /admin/* endpoints called by the dashboard. The same
# value is embedded in the dashboard HTML at generation time and sent as
# X-Admin-Token. Empty value disables admin endpoints (returns 503).
DASHBOARD_ADMIN_TOKEN = os.environ.get("DASHBOARD_ADMIN_TOKEN", "")

# Origins allowed to call /admin/* (CORS). Only the dispatch dashboard.
ADMIN_ALLOWED_ORIGINS = {"https://dispatch-dashboard.aditor.ai"}

# ── SIGNATURE VERIFICATION ────────────────────────────────────────────────────

def verify_slack_signature(req) -> bool:
    """
    Verify that the request came from Slack using HMAC-SHA256 signature.
    Returns True if valid, False otherwise.
    Skips verification if SLACK_SIGNING_SECRET is not set (dev mode).
    """
    if not SLACK_SIGNING_SECRET:
        print("[WARN] SLACK_SIGNING_SECRET not set — skipping signature verification")
        return True

    timestamp = req.headers.get("X-Slack-Request-Timestamp", "")
    slack_sig  = req.headers.get("X-Slack-Signature", "")

    if not timestamp or not slack_sig:
        return False

    # Reject requests older than 5 minutes (replay attack protection)
    try:
        if abs(time.time() - float(timestamp)) > 300:
            return False
    except ValueError:
        return False

    sig_basestring = f"v0:{timestamp}:{req.get_data(as_text=True)}"
    my_sig = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode("utf-8"),
        sig_basestring.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(my_sig, slack_sig)


# ── SLACK API HELPERS ─────────────────────────────────────────────────────────

def write_to_inbox(verb: str, card_id: str, editor_key: str, user_id: str) -> bool:
    """
    Write an action payload to the agent's filesystem inbox.
    Atomic via .tmp + rename so the reader never sees a half-written file.
    Returns True on success.
    """
    try:
        os.makedirs(ACTION_INBOX_DIR, exist_ok=True)
    except Exception as e:
        print(f"[ERROR] could not create inbox dir {ACTION_INBOX_DIR}: {e}")
        return False

    payload = {
        "ts":         time.time(),
        "verb":       verb,
        "card_id":    card_id,
        "editor_key": editor_key,
        "user_id":    user_id,
    }
    fname  = f"{int(payload['ts']*1000)}_{uuid.uuid4().hex[:8]}.json"
    final  = os.path.join(ACTION_INBOX_DIR, fname)
    tmp    = final + ".tmp"

    try:
        with open(tmp, "w") as f:
            json.dump(payload, f)
        os.rename(tmp, final)
        return True
    except Exception as e:
        print(f"[ERROR] inbox write failed for {verb}|{card_id}: {e}")
        try:
            os.remove(tmp)
        except OSError:
            pass
        return False


def replace_original(response_url: str, text: str) -> None:
    """Replace the original dispatch message with feedback text."""
    try:
        requests.post(
            response_url,
            json={"replace_original": True, "text": text},
            timeout=5,
        )
    except Exception as e:
        print(f"[WARN] replace_original failed: {e}")


# ── ROUTES ────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    """Health check endpoint for Railway."""
    return "ok", 200


@app.route("/slack/actions", methods=["POST"])
def handle_action():
    """
    Main Slack interactivity endpoint.
    Receives button click payloads from Slack, ACKs immediately,
    provides visual feedback, and relays action to the dispatch channel.
    """
    # 1. Signature verification
    if not verify_slack_signature(request):
        print("[ERROR] Invalid Slack signature")
        return jsonify({"error": "Invalid signature"}), 401

    # 2. Parse payload
    raw_payload = request.form.get("payload", "")
    if not raw_payload:
        return jsonify({"error": "No payload"}), 400

    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON payload"}), 400

    # 3. Extract action info
    actions = payload.get("actions", [])
    if not actions:
        return "", 200  # No actions — ack and exit

    action       = actions[0]
    action_id    = action.get("action_id", "")
    user_id      = payload.get("user", {}).get("id", "unknown")
    response_url = payload.get("response_url", "")

    print(f"[ACTION] action_id={action_id} user={user_id}")

    # 4. Parse action_id — format: "accept:{card_id}:{editor_key}"
    parts = action_id.split(":", 2)
    if len(parts) < 2:
        print(f"[WARN] Unexpected action_id format: {action_id}")
        return "", 200

    verb       = parts[0]          # "accept" or "decline"
    card_id    = parts[1]          # Trello card ID
    editor_key = parts[2] if len(parts) > 2 else "unknown"

    # 5. Immediate visual feedback — replace the Slack message buttons
    if verb == "accept":
        feedback = f"✅ *Accepted!* You're on this one. Trello card will be updated shortly."
    elif verb == "decline":
        feedback = f"❌ *Declined.* Got it — we'll find another editor."
    elif verb == "approve_dispatch":
        feedback = f"✅ *Approved.* Dispatching to the editor now…"
    elif verb == "reject_dispatch":
        feedback = f"❌ *Rejected.* Card will not be dispatched."
    elif verb == "remove_card":
        feedback = f"🚫 *Removed from rotation.* This card will not be dispatched again."
    else:
        feedback = f"⚡ Action received: `{action_id}`"

    if response_url:
        replace_original(response_url, feedback)

    # 6. Drop the action into the agent's filesystem inbox.
    if write_to_inbox(verb, card_id, editor_key, user_id):
        print(f"[OK] Wrote inbox entry: {verb}|{card_id}|{editor_key}|{user_id}")
    else:
        print(f"[ERROR] Inbox write failed for {verb}|{card_id} — action will be lost")

    # 7. ACK to Slack — must return 200 within 3 seconds
    return "", 200


# ── ADMIN ENDPOINTS (called by the dispatch dashboard) ───────────────────────
#
# These endpoints are gated by a shared X-Admin-Token header that matches
# DASHBOARD_ADMIN_TOKEN env var. The same token is embedded in the dashboard
# HTML at generation time. Repo is private, so the token is only readable
# by collaborators — this is the placeholder until Cloudflare Access lands
# in front of the dashboard, at which point the JWT becomes the auth.

def _apply_cors(resp):
    """Attach CORS headers if the request Origin is in the allowlist."""
    origin = request.headers.get("Origin", "")
    if origin in ADMIN_ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"]  = origin
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Admin-Token"
        resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        resp.headers["Vary"] = "Origin"
    return resp


def _require_admin_token():
    """
    Validate the X-Admin-Token header. Returns a Flask response on failure
    (caller should return it directly), or None on success.
    """
    if not DASHBOARD_ADMIN_TOKEN:
        return _apply_cors(jsonify({"error": "admin disabled — DASHBOARD_ADMIN_TOKEN not set"})), 503
    supplied = request.headers.get("X-Admin-Token", "")
    if not supplied or not hmac.compare_digest(supplied, DASHBOARD_ADMIN_TOKEN):
        print(f"[ADMIN] rejected: bad/missing X-Admin-Token from {request.headers.get('Origin','-')}")
        return _apply_cors(jsonify({"error": "unauthorized"})), 401
    return None


def _admin_dispatch_action(verb):
    """
    Shared body for the dashboard admin endpoints that act on a pending
    approval (approve_dispatch, reject_dispatch). Body must include both
    card_id and editor_key — the agent's on_*_dispatch handlers need both
    to look up the pending_approval entry and propose the correct editor.
    """
    if request.method == "OPTIONS":
        return _apply_cors(make_response("", 204))

    err = _require_admin_token()
    if err is not None:
        return err

    body = request.get_json(silent=True) or {}
    card_id    = (body.get("card_id") or "").strip()
    editor_key = (body.get("editor_key") or "").strip()
    if not card_id or not editor_key:
        return _apply_cors(jsonify({"error": "missing card_id or editor_key"})), 400

    if write_to_inbox(verb, card_id, editor_key, "dashboard"):
        print(f"[ADMIN] dashboard {verb} queued: card={card_id} editor={editor_key}")
        return _apply_cors(jsonify({"ok": True, "verb": verb, "card_id": card_id, "editor_key": editor_key}))

    return _apply_cors(jsonify({"error": "inbox write failed"})), 500


@app.route("/admin/remove_card", methods=["POST", "OPTIONS"])
def admin_remove_card():
    """
    Dashboard "Remove from rotation" button. Body: {"card_id": "..."}.
    Writes a remove_card inbox entry; the agent's poller picks it up and
    runs dispatch.on_remove_card(card_id, "dashboard").
    """
    if request.method == "OPTIONS":
        return _apply_cors(make_response("", 204))

    err = _require_admin_token()
    if err is not None:
        return err

    body = request.get_json(silent=True) or {}
    card_id = (body.get("card_id") or "").strip()
    if not card_id:
        return _apply_cors(jsonify({"error": "missing card_id"})), 400

    user_id = "dashboard"
    if write_to_inbox("remove_card", card_id, "unknown", user_id):
        print(f"[ADMIN] dashboard remove_card queued: card={card_id}")
        return _apply_cors(jsonify({"ok": True, "card_id": card_id}))

    return _apply_cors(jsonify({"error": "inbox write failed"})), 500


@app.route("/admin/approve_dispatch", methods=["POST", "OPTIONS"])
def admin_approve_dispatch():
    """
    Dashboard "Approve" button on a pending-approval card. Body:
    {"card_id": "...", "editor_key": "..."}. The agent's
    dispatch.on_approve_dispatch handles re-ranking if the editor is no
    longer available, exactly like the Slack approval flow.
    """
    return _admin_dispatch_action("approve_dispatch")


@app.route("/admin/reject_dispatch", methods=["POST", "OPTIONS"])
def admin_reject_dispatch():
    """
    Dashboard "Skip" button on a pending-approval card. Body:
    {"card_id": "...", "editor_key": "..."}. Records the editor in
    declined_by and rotates to the next-best, mirroring Tim's Reject
    button in Slack.
    """
    return _admin_dispatch_action("reject_dispatch")


# ── ENTRY POINT ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port)
