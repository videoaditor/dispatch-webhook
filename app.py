#!/usr/bin/env python3
"""
app.py — Slack interactivity webhook + dashboard API + health endpoint

Deployed as dispatch-webhook.service (gunicorn) on the Hetzner Aditor server
behind dispatch.aditor.ai. Receives Slack button click payloads, writes them
to /opt/dispatch-agent/action_inbox/ as JSON files, and exposes read-only
APIs for the dashboard SPA and external health monitoring.

Endpoints:
  POST /slack/actions          — Slack interactivity (button clicks)
  GET  /health                 — Health snapshot for n8n monitor (no auth, read-only)
  GET  /api/state              — Dashboard SPA snapshot (admin token required)
  POST /admin/remove_card      — Dashboard admin action
  POST /admin/approve_dispatch — Dashboard admin action
  POST /admin/reject_dispatch  — Dashboard admin action

Environment variables (loaded by systemd from /opt/dispatch-webhook/.env):
  SLACK_BOT_TOKEN        Slack bot token
  SLACK_SIGNING_SECRET   Slack request signing secret
  DASHBOARD_ADMIN_TOKEN  Shared secret for /admin/* and /api/state
  ACTION_INBOX_DIR       Defaults to /opt/dispatch-agent/action_inbox
  DISPATCH_AGENT_DIR     Defaults to /opt/dispatch-agent
"""

import hmac
import hashlib
import shutil
import time
import uuid
import json
import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

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
    """
    Health snapshot for external monitors (n8n). Read-only — never calls
    Trello/Slack/Airtable. Aggregates filesystem signals written by the
    dispatch-agent scheduler and reports a top-level status with reasons.
    """
    out = {
        "status":         "ok",
        "checked_at":     datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scheduler":      _scheduler_health(),
        "inbox":          _inbox_health(),
        "state":          _state_health(),
        "drift":          _drift_health(),
        "external_apis":  {"airtable": _airtable_health()},
        "disk":           _disk_health(),
    }
    out["status"], out["reasons"] = _derive_status(out)
    return jsonify(out)


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
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
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


# ── READ API (called by the dispatch dashboard SPA) ──────────────────────────

# Paths on the same host as the dispatch-agent. The webhook reads these files
# directly; both services live under /opt and have permission to read each
# other's state. Overridable for non-prod runs.
DISPATCH_AGENT_DIR = os.environ.get("DISPATCH_AGENT_DIR", "/opt/dispatch-agent")
_STATE_FILE       = os.path.join(DISPATCH_AGENT_DIR, "dispatch_state.json")
_ACTION_LOG_FILE  = os.path.join(DISPATCH_AGENT_DIR, "action_log.jsonl")
_TRUST_FILE       = os.path.join(DISPATCH_AGENT_DIR, "trust_events.json")
_REGISTRY_FILE    = os.path.join(DISPATCH_AGENT_DIR, "editor_registry.json")


def _safe_load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[WARN] _safe_load_json {path}: {e}")
        return default


def _safe_tail_jsonl(path, n=500):
    """Read the last N JSON lines from a JSONL file. Skips malformed lines."""
    try:
        # Tail efficiently for big files: seek to a window from the end and
        # parse forward. 500 events × ~250 bytes ≈ 125KB; 256KB is plenty
        # of margin.
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            window = min(size, 256 * 1024)
            f.seek(size - window)
            chunk = f.read().decode("utf-8", errors="replace")
        lines = chunk.splitlines()
        if size > window:
            lines = lines[1:]  # drop the partial first line we may have sliced
        events = []
        for line in lines[-n:]:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"[WARN] _safe_tail_jsonl {path}: {e}")
        return []


@app.route("/api/state", methods=["GET", "OPTIONS"])
def api_state():
    """
    Snapshot of everything the dashboard SPA needs in one round-trip:
    dispatched cards, pending approvals, removed cards, recent events,
    weekly trust events, and a slim editor lookup. Same auth as /admin/*.
    """
    if request.method == "OPTIONS":
        return _apply_cors(make_response("", 204))

    err = _require_admin_token()
    if err is not None:
        return err

    state    = _safe_load_json(_STATE_FILE,    default={"dispatched": {}, "pending_approval": {}})
    events   = _safe_tail_jsonl(_ACTION_LOG_FILE, n=500)
    trust    = _safe_load_json(_TRUST_FILE,    default=[])
    registry = _safe_load_json(_REGISTRY_FILE, default={"editors": {}})

    editors_slim = {
        k: {
            "name":       ed.get("name", k),
            "label_name": ed.get("label_name", ""),
            "tier":       ed.get("tier", ""),
            "approved":   ed.get("approved", True),
            "brands":     ed.get("brands", []),
            "slack_id":   ed.get("slack_id", ""),
        }
        for k, ed in registry.get("editors", {}).items()
    }

    payload = {
        "server_time":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dispatched":       state.get("dispatched", {}),
        "pending_approval": state.get("pending_approval", {}),
        "removed_cards":    state.get("removed_cards", {}),
        "events":           events[-300:],   # most recent 300 — 1-2 weeks worth
        "trust_events":     trust[-500:],
        "editors":          editors_slim,
    }

    resp = jsonify(payload)
    resp.headers["Cache-Control"] = "no-store"
    return _apply_cors(resp)


# ── HEALTH HELPERS ────────────────────────────────────────────────────────────
# All thresholds for the /health endpoint live here so they're easy to tune.

CET_TZ = ZoneInfo("Europe/Berlin")

# Files written by the dispatch-agent scheduler. Paths resolve via DISPATCH_AGENT_DIR.
_HEARTBEAT_FILE       = os.path.join(DISPATCH_AGENT_DIR, "heartbeat.json")
_SCHEDULER_STATE_FILE = os.path.join(DISPATCH_AGENT_DIR, "scheduler_state.json")
_DRIFT_REPORT_FILE    = os.path.join(DISPATCH_AGENT_DIR, "drift_report.json")
_AIRTABLE_OK_FILE     = os.path.join(DISPATCH_AGENT_DIR, "airtable_last_success.json")
_AIRTABLE_ERR_FILE    = os.path.join(DISPATCH_AGENT_DIR, "airtable_errors.jsonl")

# Scheduler windows (hour in Europe/Berlin). Keep in sync with scheduler.py.
_WINDOWS = [
    ("w1",  "08:00",  8, False),  # (key, label, hour, conditional)
    ("w2",  "13:00", 13, False),
    ("w2b", "17:00", 17, True),   # conditional — only fires if needs_recheck=True
    ("w3",  "21:00", 21, False),
]
_WINDOW_GRACE_MIN = 5  # minutes after the trigger before "missed"

# Thresholds for status promotion. Tune here; n8n side mirrors these but
# evaluates independently so the workflow doesn't fully trust this code.
_HB_WARN_S         = 120     # heartbeat older than this → warn
_HB_RED_S          = 600     # … and this → red
_INBOX_WARN_DEPTH  = 10
_INBOX_WARN_OLDEST = 300     # seconds
_STATE_WARN_AGE_S  = 86400   # state file untouched for a day → warn
_DISK_WARN_PCT     = 80
_DISK_RED_PCT      = 95

# Airtable error thresholds. consecutive_failures captures "the API is broken
# right now"; errors_last_15min catches a spray of intermittent failures even
# if individual calls recover. last_success_age_s catches a quiet stall where
# nothing is calling Airtable (could be benign overnight, less so during day).
_AT_CONSEC_RED       = 3
_AT_CONSEC_WARN      = 1
_AT_15MIN_RED        = 5
_AT_15MIN_WARN       = 2
_AT_NO_SUCCESS_RED_S = 1800   # 30 min of no successful call → red


def _file_mtime_age_s(path):
    try:
        return max(0, int(time.time() - os.path.getmtime(path)))
    except OSError:
        return None


def _scheduler_health():
    hb       = _safe_load_json(_HEARTBEAT_FILE, default=None)
    hb_age   = _file_mtime_age_s(_HEARTBEAT_FILE)
    sched    = _safe_load_json(_SCHEDULER_STATE_FILE, default={})
    state    = _safe_load_json(_STATE_FILE, default={})
    ran      = (sched or {}).get("ran_today", {})

    now_cet  = datetime.now(CET_TZ)
    today    = now_cet.strftime("%Y-%m-%d")
    minutes  = now_cet.hour * 60 + now_cet.minute

    windows  = {}
    for key, label, hour, conditional in _WINDOWS:
        trigger = hour * 60
        if ran.get(key) == today:
            windows[label] = "ran"
        elif minutes < trigger:
            windows[label] = "pending"
        elif minutes < trigger + _WINDOW_GRACE_MIN:
            windows[label] = "pending"   # within grace window
        else:
            # Past trigger + grace, did not run today.
            if conditional:
                # w2b only fires if Window 2 set needs_recheck=True. If the
                # flag was never set today, skipping is correct, not a miss.
                windows[label] = "skipped" if not state.get("needs_recheck") else "missed"
            else:
                windows[label] = "missed"

    return {
        "heartbeat_present": hb is not None,
        "heartbeat_age_s":   hb_age,
        "loop_iteration":    (hb or {}).get("loop_iteration"),
        "started_at":        (hb or {}).get("started_at"),
        "git_sha":           (hb or {}).get("git_sha"),
        "windows_today":     windows,
    }


def _inbox_health():
    try:
        entries = [
            f for f in os.listdir(ACTION_INBOX_DIR)
            if f.endswith(".json") and not f.endswith(".tmp")
        ]
    except FileNotFoundError:
        return {"depth": 0, "oldest_age_s": None}
    if not entries:
        return {"depth": 0, "oldest_age_s": None}
    oldest = min(
        (_file_mtime_age_s(os.path.join(ACTION_INBOX_DIR, f)) or 0)
        for f in entries
    )
    return {"depth": len(entries), "oldest_age_s": oldest}


def _state_health():
    try:
        with open(_STATE_FILE) as f:
            data = json.load(f)
        return {
            "age_s":              _file_mtime_age_s(_STATE_FILE),
            "parseable":          True,
            "dispatched_count":   len(data.get("dispatched", {})),
            "pending_count":      len(data.get("pending_approval", {})),
        }
    except FileNotFoundError:
        return {"age_s": None, "parseable": False, "dispatched_count": 0, "pending_count": 0}
    except (json.JSONDecodeError, OSError):
        return {
            "age_s":     _file_mtime_age_s(_STATE_FILE),
            "parseable": False, "dispatched_count": 0, "pending_count": 0,
        }


def _drift_health():
    # Phase 2 will populate this. Stub keeps the response shape stable.
    if not os.path.exists(_DRIFT_REPORT_FILE):
        return {
            "available":      False,
            "report_age_s":   None,
            "orphans":        0, "untracked":     0,
            "stale_pendings": 0, "label_mismatch":0, "status_mismatch": 0,
            "samples":        {},
        }
    report = _safe_load_json(_DRIFT_REPORT_FILE, default=None) or {}
    return {
        "available":      True,
        "report_age_s":   _file_mtime_age_s(_DRIFT_REPORT_FILE),
        "orphans":        report.get("orphans", 0),
        "untracked":      report.get("untracked", 0),
        "stale_pendings": report.get("stale_pendings", 0),
        "label_mismatch": report.get("label_mismatch", 0),
        "status_mismatch":report.get("status_mismatch", 0),
        "samples":        report.get("samples", {}),
    }


def _parse_iso_utc(ts):
    if not ts:
        return None
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def _airtable_health():
    """
    Compute Airtable signal from telemetry files written by
    airtable_telemetry.record_success/record_failure:
      - airtable_last_success.json  (atomic, single ts)
      - airtable_errors.jsonl       (append-only)

    consecutive_failures = number of trailing error entries that are newer
    than the most recent success. errors_last_15min counts entries by ts.
    """
    have_ok  = os.path.exists(_AIRTABLE_OK_FILE)
    have_err = os.path.exists(_AIRTABLE_ERR_FILE)
    if not have_ok and not have_err:
        return {"available": False}

    last_success_age_s = _file_mtime_age_s(_AIRTABLE_OK_FILE) if have_ok else None
    last_success_ts    = None
    if have_ok:
        ok = _safe_load_json(_AIRTABLE_OK_FILE, default=None)
        if isinstance(ok, dict):
            last_success_ts = _parse_iso_utc(ok.get("ts"))

    last_error_ts        = None
    last_error_code      = None
    errors_last_15min    = 0
    consecutive_failures = 0

    if have_err:
        # _safe_tail_jsonl is defined above; 500 lines is ~125KB of context,
        # more than enough to cover any plausible 15 min window of failures.
        recent = _safe_tail_jsonl(_AIRTABLE_ERR_FILE, n=500)
        now    = datetime.now(timezone.utc)
        cutoff = now.timestamp() - 15 * 60

        for entry in recent:
            ts_str = entry.get("ts")
            ts_dt  = _parse_iso_utc(ts_str)
            if ts_dt and ts_dt.timestamp() >= cutoff:
                errors_last_15min += 1

        if recent:
            last_entry      = recent[-1]
            last_error_ts   = last_entry.get("ts")
            last_error_code = last_entry.get("status_code")

            # Walk backwards counting failures newer than last success.
            for entry in reversed(recent):
                ts_dt = _parse_iso_utc(entry.get("ts"))
                if ts_dt is None:
                    break
                if last_success_ts and ts_dt <= last_success_ts:
                    break
                consecutive_failures += 1

    return {
        "available":            True,
        "last_success_age_s":   last_success_age_s,
        "last_error_ts":        last_error_ts,
        "last_error_code":      last_error_code,
        "errors_last_15min":    errors_last_15min,
        "consecutive_failures": consecutive_failures,
    }


def _disk_health():
    try:
        usage = shutil.disk_usage("/opt")
        return {"opt_used_pct": int(round(100 * usage.used / usage.total))}
    except OSError:
        return {"opt_used_pct": None}


def _derive_status(snapshot):
    """
    Return (status, reasons[]). Status is the worst of any tripped threshold.
    Reasons are short strings n8n can present to the operator.
    """
    reasons   = []
    severity  = 0   # 0=ok, 1=warn, 2=red

    def bump(level, msg):
        nonlocal severity
        if level > severity:
            severity = level
        reasons.append(msg)

    sched = snapshot["scheduler"]
    hb    = sched.get("heartbeat_age_s")
    if not sched.get("heartbeat_present") or hb is None:
        bump(2, "scheduler heartbeat missing")
    elif hb > _HB_RED_S:
        bump(2, f"scheduler heartbeat stale ({hb}s)")
    elif hb > _HB_WARN_S:
        bump(1, f"scheduler heartbeat slow ({hb}s)")

    for label, status in (sched.get("windows_today") or {}).items():
        if status == "missed":
            bump(2, f"window {label} missed")

    inbox = snapshot["inbox"]
    if inbox.get("depth", 0) > _INBOX_WARN_DEPTH:
        bump(1, f"inbox backlog ({inbox['depth']} files)")
    if (inbox.get("oldest_age_s") or 0) > _INBOX_WARN_OLDEST:
        bump(1, f"oldest inbox entry {inbox['oldest_age_s']}s")

    state = snapshot["state"]
    if not state.get("parseable"):
        bump(2, "dispatch_state.json unparseable or missing")
    elif (state.get("age_s") or 0) > _STATE_WARN_AGE_S:
        bump(1, f"dispatch_state.json untouched {state['age_s']}s")

    drift = snapshot["drift"]
    if drift.get("available"):
        if drift.get("orphans", 0) > 0:
            bump(2, f"drift: {drift['orphans']} orphans in state")
        if drift.get("stale_pendings", 0) > 0:
            bump(2, f"drift: {drift['stale_pendings']} stale pendings")
        if drift.get("untracked", 0) > 0:
            bump(1, f"drift: {drift['untracked']} untracked in Trello")
        if drift.get("label_mismatch", 0) > 0:
            bump(1, f"drift: {drift['label_mismatch']} label mismatches")
        if drift.get("status_mismatch", 0) > 0:
            bump(1, f"drift: {drift['status_mismatch']} status mismatches")

    airtable = (snapshot.get("external_apis") or {}).get("airtable") or {}
    if airtable.get("available"):
        cf = airtable.get("consecutive_failures") or 0
        e15 = airtable.get("errors_last_15min") or 0
        if cf >= _AT_CONSEC_RED:
            bump(2, f"Airtable: {cf} consecutive failures")
        elif cf >= _AT_CONSEC_WARN:
            bump(1, f"Airtable: {cf} consecutive failure(s)")
        if e15 >= _AT_15MIN_RED:
            bump(2, f"Airtable: {e15} errors in last 15min")
        elif e15 >= _AT_15MIN_WARN:
            bump(1, f"Airtable: {e15} errors in last 15min")
        age = airtable.get("last_success_age_s")
        if age is not None and age > _AT_NO_SUCCESS_RED_S:
            bump(2, f"Airtable: no success in {age}s")

    disk = snapshot["disk"]
    used = disk.get("opt_used_pct")
    if used is not None:
        if used > _DISK_RED_PCT:
            bump(2, f"/opt {used}% full")
        elif used > _DISK_WARN_PCT:
            bump(1, f"/opt {used}% full")

    return (["ok", "warn", "red"][severity], reasons)


# ── ENTRY POINT ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port)
