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
import json
import os
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# ── CONFIG (via environment variables) ────────────────────────────────────────

SLACK_BOT_TOKEN      = os.environ.get("SLACK_BOT_TOKEN", "")
SLACK_SIGNING_SECRET = os.environ.get("SLACK_SIGNING_SECRET", "")

# Channel where DISPATCH_ACTION messages are posted for the heartbeat to read.
# Default: automations channel (C07UL6BAG1Z). Override with DISPATCH_CHANNEL env var.
DISPATCH_CHANNEL = os.environ.get("DISPATCH_CHANNEL", "C07UL6BAG1Z")

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

def post_to_slack(channel: str, text: str) -> dict:
    """Post a plain message to a Slack channel using the bot token."""
    resp = requests.post(
        "https://slack.com/api/chat.postMessage",
        headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
        json={
            "channel": channel,
            "text": text,
            "unfurl_links": False,
            "unfurl_media": False,
        },
        timeout=5,
    )
    return resp.json()


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
    else:
        feedback = f"⚡ Action received: `{action_id}`"

    if response_url:
        replace_original(response_url, feedback)

    # 6. Post DISPATCH_ACTION to the automations/dispatch channel
    #    Format: DISPATCH_ACTION: {verb}|{card_id}|{editor_key}|{user_id}
    dispatch_text = f"DISPATCH_ACTION: {verb}|{card_id}|{editor_key}|{user_id}"
    result = post_to_slack(DISPATCH_CHANNEL, dispatch_text)
    if not result.get("ok"):
        print(f"[WARN] Failed to post dispatch action: {result.get('error')}")
    else:
        print(f"[OK] Posted dispatch action to {DISPATCH_CHANNEL}: {dispatch_text}")

    # 7. ACK to Slack — must return 200 within 3 seconds
    return "", 200


# ── ENTRY POINT ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port)
