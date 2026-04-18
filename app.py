import sqlite3
import json
import re
import base64
import urllib.request
from datetime import datetime
from flask import Flask, jsonify, request, render_template_string, Response
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

app = Flask(__name__)
DB_PATH = "/home/hack3r/Web/PurrfectSC/message_loggerr.db"

VIDEO_PREFIXES = {"/4/", "/3/", "/u/"}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_indexes():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE INDEX IF NOT EXISTS idx_msg_user_id   ON messages(user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_msg_username  ON messages(username)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_msg_conv_id   ON messages(conversation_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_stories_uid   ON stories(user_id)")
    conn.commit()
    conn.close()
    print("Indexes ready.")


ensure_indexes()


_SYSTEM_STRINGS = {
    "CHAT", "SNAP", "EXTERNAL_MEDIA", "NOTE", "STICKER", "SHARE",
    "UNKNOWN", "NONE", "NORMAL", "STATUS", "OPEN", "CLOSED",
    "TRUE", "FALSE", "NULL", "SAVE_POLICY", "ERASABLE", "SAVEABLE",
}

BOLT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.3"
)


# ── Protobuf helpers (no external deps) ──────────────────────────────────────

def _read_varint(data, pos):
    result = shift = 0
    while pos < len(data):
        b = data[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def _proto_fields(data):
    fields = {}
    pos = 0
    while pos < len(data):
        try:
            tag, pos = _read_varint(data, pos)
        except Exception:
            break
        field_num = tag >> 3
        wire_type = tag & 0x7
        try:
            if wire_type == 0:
                val, pos = _read_varint(data, pos)
                fields.setdefault(field_num, []).append(("varint", val))
            elif wire_type == 2:
                length, pos = _read_varint(data, pos)
                val = data[pos:pos + length]; pos += length
                fields.setdefault(field_num, []).append(("bytes", val))
            elif wire_type == 5:
                fields.setdefault(field_num, []).append(("fixed32", data[pos:pos+4])); pos += 4
            elif wire_type == 1:
                fields.setdefault(field_num, []).append(("fixed64", data[pos:pos+8])); pos += 8
            else:
                break
        except Exception:
            break
    return fields


def _follow_proto(data, path):
    cur = data
    for field_num in path:
        fields = _proto_fields(cur)
        entries = fields.get(field_num, [])
        if not entries:
            return None
        wt, val = entries[0]
        if wt != "bytes":
            return None
        cur = val
    return cur


def _decode_enc_pair(data):
    """Extract (key_bytes, iv_bytes) from a proto with field 1=key and field 2=iv."""
    ef = _proto_fields(data)
    k = ef.get(1, [None])[0]
    v = ef.get(2, [None])[0]
    if not k or not v:
        return None, None
    try:
        key = base64.b64decode(k[1].strip())
        iv  = base64.b64decode(v[1].strip())
        return key, iv
    except Exception:
        # raw bytes fallback
        if k[0] == "bytes" and v[0] == "bytes":
            return k[1], v[1]
    return None, None


def extract_snap_bolt(message_data_blob):
    """Return (bolt_key_b64url, key_bytes|None, iv_bytes|None) for a SNAP/EXTERNAL_MEDIA msg."""
    try:
        data = json.loads(message_data_blob)
        content = data.get("mMessageContent", {})

        # Bolt key from mRemoteMediaReferences[*].mMediaReferences[*].mContentObject
        bolt_key = None
        for ref in content.get("mRemoteMediaReferences", []):
            for mref in ref.get("mMediaReferences", []):
                obj = mref.get("mContentObject", [])
                if obj:
                    b = bytes([x % 256 for x in obj])
                    bolt_key = base64.urlsafe_b64encode(b).decode()
                    break
            if bolt_key:
                break
        if not bolt_key:
            return None, None, None

        # Encryption key/iv from mContent protobuf
        content_arr = content.get("mContent", [])
        if not content_arr:
            return bolt_key, None, None
        proto = bytes([x % 256 for x in content_arr])

        # SNAP path  [11,5,1,1,4]  (base64-encoded key/iv strings)
        for path in ([11, 5, 1, 1, 4], [11, 5, 1, 1, 19]):
            enc = _follow_proto(proto, path)
            if enc:
                key, iv = _decode_enc_pair(enc)
                if key and iv:
                    return bolt_key, key, iv

        # EXTERNAL_MEDIA path  [3,3,5,1,1,4]
        for path in ([3, 3, 5, 1, 1, 4], [3, 3, 5, 1, 1, 19]):
            enc = _follow_proto(proto, path)
            if enc:
                key, iv = _decode_enc_pair(enc)
                if key and iv:
                    return bolt_key, key, iv

        return bolt_key, None, None
    except Exception:
        return None, None, None


def extract_chat_text(message_data_blob):
    try:
        data = json.loads(message_data_blob)
        content = data.get("mMessageContent", {}).get("mContent", [])
        if not content:
            return ""
        b = bytes([x % 256 for x in content])
        # Match printable ASCII + common extended latin
        strings = re.findall(rb"[\x20-\x7e\xc0-\xff]{2,}", b)
        results = []
        for s in strings:
            try:
                decoded = s.decode("utf-8", errors="replace")
            except Exception:
                decoded = s.decode("latin-1")
            # Skip base64/binary blobs
            if re.match(r"^[A-Za-z0-9+/=]{20,}$", decoded):
                continue
            # Skip UUIDs
            if re.match(r"^[0-9a-f\-]{32,}$", decoded):
                continue
            # Skip known system enum strings
            if decoded.strip() in _SYSTEM_STRINGS:
                continue
            # Skip strings with no lowercase (all-caps system tokens)
            if len(decoded) <= 10 and decoded.isupper():
                continue
            if len(decoded) >= 2:
                results.append(decoded)
        return " ".join(results).strip()
    except Exception:
        return ""


def extract_snap_key(message_data_blob):
    try:
        data = json.loads(message_data_blob)
        refs = data.get("mMessageContent", {}).get("mRemoteMediaReferences", [])
        seen = set()
        keys = []
        for ref in refs:
            for mref in ref.get("mMediaReferences", []):
                obj = mref.get("mContentObject", [])
                if obj:
                    b = bytes([x % 256 for x in obj])
                    strings = re.findall(rb"[\x20-\x7e]{10,}", b)
                    for s in strings:
                        decoded = s.decode("latin-1")
                        if re.match(r"^[A-Za-z0-9_\-+/]{10,25}$", decoded):
                            if decoded not in seen:
                                seen.add(decoded)
                                keys.append(decoded)
        return keys
    except Exception:
        return []


def is_video_url(url):
    if not url:
        return False
    for prefix in VIDEO_PREFIXES:
        if prefix in url:
            return True
    return False


def fmt_ts(ts_ms):
    if not ts_ms:
        return ""
    try:
        return datetime.fromtimestamp(ts_ms / 1000).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(ts_ms)


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/stats")
def api_stats():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(DISTINCT username) FROM messages")
    users = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM messages")
    msgs = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM stories")
    stories = cur.fetchone()[0]
    conn.close()
    return jsonify({"users": users, "messages": msgs, "stories": stories})


@app.route("/api/users")
def api_users():
    q = request.args.get("q", "").strip().lower()
    sort = request.args.get("sort", "recent")
    order = "lower(username) ASC" if sort == "az" else "last_ts DESC"
    limit = 100 if q else 200
    conn = get_db()
    cur = conn.cursor()
    if q:
        cur.execute(
            f"""SELECT username, COUNT(*) as msg_count, MAX(send_timestamp) as last_ts
               FROM messages WHERE lower(username) LIKE ?
               GROUP BY username ORDER BY {order} LIMIT {limit}""",
            (f"%{q}%",),
        )
    else:
        cur.execute(
            f"""SELECT username, COUNT(*) as msg_count, MAX(send_timestamp) as last_ts
               FROM messages GROUP BY username ORDER BY {order} LIMIT {limit}"""
        )
    rows = cur.fetchall()
    conn.close()
    return jsonify(
        [
            {
                "username": r["username"],
                "msg_count": r["msg_count"],
                "last_ts": fmt_ts(r["last_ts"]),
            }
            for r in rows
        ]
    )


@app.route("/api/story-users")
def api_story_users():
    q = request.args.get("q", "").strip().lower()
    sort = request.args.get("sort", "recent")
    order = "lower(COALESCE(username, s.user_id)) ASC" if sort == "az" else "last_ts DESC"
    conn = get_db()
    cur = conn.cursor()
    base = """
        SELECT s.user_id,
               (SELECT MAX(username) FROM messages WHERE user_id = s.user_id) as username,
               COUNT(*) as story_count,
               MAX(s.added_timestamp) as last_ts
        FROM stories s
        GROUP BY s.user_id
    """
    if q:
        cur.execute(
            base + f" HAVING lower(COALESCE(username, s.user_id)) LIKE ? ORDER BY {order} LIMIT 100",
            (f"%{q}%",),
        )
    else:
        cur.execute(base + f" ORDER BY {order} LIMIT 200")
    rows = cur.fetchall()
    conn.close()
    return jsonify(
        [
            {
                "user_id": r["user_id"],
                "display": r["username"] or r["user_id"],
                "has_username": bool(r["username"]),
                "story_count": r["story_count"],
                "last_ts": fmt_ts(r["last_ts"]),
            }
            for r in rows
        ]
    )


@app.route("/api/user-id/<username>")
def api_user_id(username):
    """Fast lookup: username → user_id for stories."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT DISTINCT user_id FROM messages WHERE username = ? LIMIT 1",
        (username,),
    )
    row = cur.fetchone()
    conn.close()
    return jsonify({"user_id": row["user_id"] if row else None})


@app.route("/api/stories/<user_id>")
def api_stories(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """SELECT url, posted_timestamp, added_timestamp
           FROM stories WHERE user_id = ?
           ORDER BY posted_timestamp DESC""",
        (user_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return jsonify(
        [
            {
                "url": r["url"],
                "posted": fmt_ts(r["posted_timestamp"]),
                "added": fmt_ts(r["added_timestamp"]),
                "is_video": is_video_url(r["url"]),
            }
            for r in rows
        ]
    )


@app.route("/api/owner")
def api_owner():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT username FROM messages GROUP BY username ORDER BY COUNT(*) DESC LIMIT 1"
    )
    row = cur.fetchone()
    conn.close()
    return jsonify({"username": row["username"] if row else None})


def _parse_message(r, owner):
    try:
        data = json.loads(r["message_data"])
    except Exception:
        data = {}

    content_type = data.get("mMessageContent", {}).get("mContentType", "UNKNOWN")
    meta = data.get("mMetadata", {})
    has_audio = data.get("mMessageContent", {}).get("mSnapDisplayInfo", {}).get("mHasAudio", False)

    text = ""
    snap_keys = []
    if r["edit_text"]:
        text = r["edit_text"]
    elif content_type == "CHAT":
        text = extract_chat_text(r["message_data"])
    elif content_type in ("SNAP", "EXTERNAL_MEDIA"):
        snap_keys = extract_snap_key(r["message_data"])

    sender = r["username"]
    return {
        "id": r["id"],
        "sender": sender,
        "is_me": sender == owner,
        "ts": fmt_ts(r["send_timestamp"]),
        "ts_raw": r["send_timestamp"],
        "type": content_type,
        "text": text,
        "snap_keys": snap_keys,
        "has_audio": has_audio,
        "edited": meta.get("mIsEdited", False),
        "deleted": meta.get("mTombstone", False),
        "seen": len(meta.get("mSeenBy", [])) > 0,
        "saved": len(meta.get("mSavedBy", [])) > 0,
        "screenshot": len(meta.get("mScreenShottedBy", [])) > 0,
        "conv_id": r["conversation_id"],
    }


@app.route("/api/conversation/<username>")
def api_conversation(username):
    conn = get_db()
    cur = conn.cursor()

    # Detect owner (most frequent sender)
    cur.execute(
        "SELECT username FROM messages GROUP BY username ORDER BY COUNT(*) DESC LIMIT 1"
    )
    owner_row = cur.fetchone()
    owner = owner_row["username"] if owner_row else None

    # Find all conversation_ids where this user appears as sender
    cur.execute(
        "SELECT DISTINCT conversation_id FROM messages WHERE username = ?",
        (username,),
    )
    conv_ids = [r["conversation_id"] for r in cur.fetchall()]

    if not conv_ids:
        conn.close()
        return jsonify([])

    # Fetch ALL messages in those conversations (from every sender)
    placeholders = ",".join("?" * len(conv_ids))
    cur.execute(
        f"""SELECT m.id, m.message_id, m.conversation_id, m.username,
                  m.send_timestamp, m.group_title, m.message_data,
                  ce.message_text as edit_text
           FROM messages m
           LEFT JOIN chat_edits ce ON m.message_id = ce.message_id
               AND m.conversation_id = ce.conversation_id
           WHERE m.conversation_id IN ({placeholders})
           ORDER BY m.send_timestamp ASC""",
        conv_ids,
    )
    rows = cur.fetchall()
    conn.close()

    return jsonify([_parse_message(r, owner) for r in rows])


def _detect_media(data, fallback_ct="application/octet-stream"):
    if data[:3] == b"\xff\xd8\xff":
        return "jpg", "image/jpeg"
    if data[:4] == b"\x89PNG":
        return "png", "image/png"
    if data[:3] == b"GIF":
        return "gif", "image/gif"
    if data[4:8] in (b"ftyp", b"mdat", b"moov") or data[:4] in (
        b"\x00\x00\x00\x18", b"\x00\x00\x00\x1c", b"\x00\x00\x00\x20",
        b"\x00\x00\x00\x14", b"\x00\x00\x00\x08",
    ):
        return "mp4", "video/mp4"
    return "bin", fallback_ct


def _unwrap_snap(data, fallback_ct="application/octet-stream"):
    """Unwrap Snapchat's overlay ZIP container if present, return (bytes, ext, ct)."""
    import zipfile, io
    if data[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = zf.namelist()
                # Find the media entry (not the overlay)
                media_name = next(
                    (n for n in names if n.startswith("media")),
                    names[0] if names else None,
                )
                if media_name:
                    inner = zf.read(media_name)
                    ext, ct = _detect_media(inner, fallback_ct)
                    return inner, ext, ct
        except Exception:
            pass
    ext, ct = _detect_media(data, fallback_ct)
    return data, ext, ct


@app.route("/api/snap-info/<int:msg_id>")
def api_snap_info(msg_id):
    """Return bolt_key and whether encryption keys are available."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT message_data FROM messages WHERE id = ?", (msg_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    bolt_key, key_bytes, iv_bytes = extract_snap_bolt(row["message_data"])
    return jsonify({
        "bolt_key": bolt_key,
        "has_encryption": bool(key_bytes and iv_bytes),
    })


@app.route("/api/snap-download/<int:msg_id>")
def api_snap_download(msg_id):
    """Proxy-download a snap: resolve via Bolt, decrypt with AES-CBC, stream to browser."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT message_data FROM messages WHERE id = ?", (msg_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404

    bolt_key, key_bytes, iv_bytes = extract_snap_bolt(row["message_data"])
    if not bolt_key:
        return jsonify({"error": "no media in this message"}), 400

    bolt_url = f"https://gcp.api.snapchat.com/bolt-http/resolve?co={bolt_key}"
    try:
        req = urllib.request.Request(bolt_url, headers={"User-Agent": BOLT_UA})
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw_bytes = resp.read()
            content_type = resp.headers.get("Content-Type", "application/octet-stream")
    except Exception as e:
        return jsonify({"error": f"fetch failed: {e}"}), 502

    if key_bytes and iv_bytes:
        try:
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            raw_bytes = unpad(cipher.decrypt(raw_bytes), AES.block_size)
        except Exception:
            pass

    raw_bytes, ext, ct = _unwrap_snap(raw_bytes, content_type)

    r = Response(raw_bytes, mimetype=ct)
    r.headers["Content-Disposition"] = f'attachment; filename="snap_{msg_id}.{ext}"'
    return r


@app.route("/api/story-download")
def api_story_download():
    """Download and decrypt a story from its CDN URL."""
    url = request.args.get("url", "")
    user_id = request.args.get("user_id", "")
    ts = request.args.get("ts", "")
    if not url:
        return jsonify({"error": "url required"}), 400

    conn = get_db()
    cur = conn.cursor()
    # Query by URL only — user_id is a hint, not required
    cur.execute(
        "SELECT encryption_key, encryption_iv FROM stories WHERE url = ? LIMIT 1",
        (url,),
    )
    row = cur.fetchone()
    conn.close()

    try:
        req = urllib.request.Request(url, headers={"User-Agent": BOLT_UA})
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw_bytes = resp.read()
    except Exception as e:
        return jsonify({"error": f"fetch failed: {e}"}), 502

    decrypted = False
    if row and row[0] and row[1]:
        try:
            key_b = bytes(row[0]) if not isinstance(row[0], (bytes, bytearray)) else row[0]
            iv_b  = bytes(row[1]) if not isinstance(row[1], (bytes, bytearray)) else row[1]
            cipher = AES.new(key_b, AES.MODE_CBC, iv_b)
            raw_bytes = unpad(cipher.decrypt(raw_bytes), AES.block_size)
            decrypted = True
        except Exception as e:
            app.logger.warning(f"Story decrypt failed for {url}: {e}")

    raw_bytes, ext, ct = _unwrap_snap(raw_bytes)

    # Sanitize ts for use in filename
    safe_ts = re.sub(r"[^\w\-]", "_", ts or "story")[:30]
    fname = f"story_{safe_ts}.{ext}"
    r = Response(raw_bytes, mimetype=ct)
    r.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
    return r


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PurrfectSC Viewer</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,sans-serif;background:#0f0f0f;color:#e0e0e0;display:flex;flex-direction:column;height:100vh}

  header{background:#1a1a2e;padding:10px 18px;display:flex;align-items:center;gap:14px;border-bottom:1px solid #2a2a4a;flex-shrink:0}
  header h1{font-size:1rem;color:#a78bfa;font-weight:700}
  .stats{font-size:0.72rem;color:#555;margin-left:auto}

  .main{display:flex;flex:1;overflow:hidden}

  /* Sidebar */
  .sidebar{width:280px;min-width:200px;display:flex;flex-direction:column;border-right:1px solid #222;flex-shrink:0;background:#111}
  .sidebar-tabs{display:flex;border-bottom:1px solid #222}
  .sidebar-tab{flex:1;padding:9px 6px;text-align:center;font-size:0.78rem;cursor:pointer;color:#666;border-bottom:2px solid transparent;transition:all .15s}
  .sidebar-tab.active{color:#a78bfa;border-bottom-color:#a78bfa;background:#161626}
  .search-box{padding:7px 10px;border-bottom:1px solid #1e1e1e;display:flex;gap:6px;align-items:center}
  .search-box input{flex:1;padding:6px 10px;background:#1a1a1a;border:1px solid #2a2a2a;border-radius:7px;color:#e0e0e0;font-size:0.82rem;outline:none;min-width:0}
  .search-box input:focus{border-color:#a78bfa}
  .sort-btn{padding:5px 8px;background:#1a1a1a;border:1px solid #2a2a2a;border-radius:7px;color:#555;cursor:pointer;font-size:0.7rem;white-space:nowrap;flex-shrink:0}
  .sort-btn.active-az{color:#a78bfa;border-color:#a78bfa}
  .list-pane{flex:1;overflow-y:auto}
  .list-item{padding:9px 13px;cursor:pointer;border-bottom:1px solid #181818;transition:background .12s}
  .list-item:hover{background:#1c1c2c}
  .list-item.active{background:#2a1f4a;border-left:3px solid #a78bfa}
  .item-name{font-size:0.85rem;font-weight:500;color:#d0d0d0}
  .item-name.no-username{color:#666;font-style:italic;font-size:0.75rem}
  .item-meta{font-size:0.68rem;color:#484848;margin-top:2px}

  /* Chat area */
  .chat-area{flex:1;display:flex;flex-direction:column;overflow:hidden;background:#0f0f0f}
  .chat-header{padding:10px 18px;background:#141414;border-bottom:1px solid #222;display:flex;align-items:center;gap:10px;flex-shrink:0;min-height:44px}
  .chat-username{font-weight:600;color:#a78bfa;font-size:0.95rem}
  .chat-sub{font-size:0.7rem;color:#444;margin-left:6px}
  .chat-tabs{display:flex;gap:4px;margin-left:auto}
  .tab-btn{padding:4px 11px;border-radius:6px;border:1px solid #2a2a2a;background:transparent;color:#666;cursor:pointer;font-size:0.75rem}
  .tab-btn.active{background:#a78bfa;color:#fff;border-color:#a78bfa}

  /* Messages */
  .messages{flex:1;overflow-y:auto;padding:14px 16px;display:flex;flex-direction:column;gap:6px}
  .msg-row{display:flex;flex-direction:column;max-width:72%}
  .msg-row.me{align-self:flex-end;align-items:flex-end}
  .msg-row.them{align-self:flex-start;align-items:flex-start}
  .msg-row.status-row{align-self:center;max-width:90%}
  .msg-sender{font-size:0.65rem;color:#555;margin-bottom:2px;padding:0 4px}
  .msg-row.me .msg-sender{color:#6d56a0}
  .msg-bubble{padding:6px 10px;border-radius:12px;max-width:100%;word-break:break-word}
  .msg-row.me .msg-bubble{background:#2a1f4a;border-bottom-right-radius:3px}
  .msg-row.them .msg-bubble{background:#1e1e1e;border-bottom-left-radius:3px}
  .msg-row.status-row .msg-bubble{background:transparent;padding:2px 8px}
  .msg-text{font-size:0.84rem;color:#d0d0d0}
  .msg-row.me .msg-text{color:#c4b5fd}
  .msg-meta{display:flex;align-items:center;gap:4px;margin-top:3px;padding:0 2px}
  .msg-ts{font-size:0.62rem;color:#383838}
  .type-pill{display:inline-block;font-size:0.6rem;padding:1px 4px;border-radius:3px;font-weight:600;vertical-align:middle}
  .pill-CHAT{background:#0d2b1a;color:#4ade80}
  .pill-SNAP{background:#0d1f2e;color:#38bdf8}
  .pill-EXTERNAL_MEDIA{background:#1e1030;color:#c084fc}
  .pill-NOTE{background:#2a2310;color:#fbbf24}
  .pill-STICKER{background:#0d2222;color:#34d399}
  .pill-SHARE{background:#2a1010;color:#f87171}
  .pill-STATUS{background:transparent;color:#333}
  .pill-UNKNOWN{background:#1a1a1a;color:#333}
  .snap-key{font-size:0.63rem;color:#3b82f6;font-family:monospace;background:#0d1520;padding:1px 5px;border-radius:3px;margin-right:3px;display:inline-block}
  .badge{font-size:0.57rem;padding:1px 4px;border-radius:3px;vertical-align:middle}
  .b-edited{background:#2a2308;color:#fbbf24}
  .b-deleted{background:#2a0d0d;color:#f87171}
  .b-saved{background:#0d1a2a;color:#60a5fa}
  .b-shot{background:#2a0d1a;color:#f472b6}
  .b-audio{background:#1a1a0d;color:#a3e635}
  .conv-sep{text-align:center;font-size:0.65rem;color:#2a2a2a;padding:8px 0;border-top:1px solid #1a1a1a;margin-top:8px}
  .spinner{width:36px;height:36px;border:3px solid #2a2a2a;border-top-color:#a78bfa;border-radius:50%;animation:spin .7s linear infinite}
  .loading-pane{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;color:#555;font-size:0.8rem}
  @keyframes spin{to{transform:rotate(360deg)}}
  .msg-search-bar{padding:6px 12px;background:#111;border-bottom:1px solid #1e1e1e;display:flex;align-items:center;gap:8px;flex-shrink:0}
  .msg-search-bar input{flex:1;padding:5px 10px;background:#1a1a1a;border:1px solid #2a2a2a;border-radius:6px;color:#e0e0e0;font-size:0.8rem;outline:none}
  .msg-search-bar input:focus{border-color:#a78bfa}
  .msg-search-count{font-size:0.7rem;color:#444;white-space:nowrap}
  .highlight{background:#4c3a00;border-radius:2px;color:#fcd34d}
  .highlight.active-match{background:#7c5c00;outline:2px solid #fcd34d}
  .nav-btn{padding:3px 8px;background:#1a1a1a;border:1px solid #2a2a2a;border-radius:5px;color:#888;cursor:pointer;font-size:0.75rem}
  .nav-btn:hover{border-color:#a78bfa;color:#a78bfa}

  /* Stories grid */
  .stories-grid{flex:1;overflow-y:auto;padding:14px;display:grid;grid-template-columns:repeat(auto-fill,160px);grid-auto-rows:260px;gap:10px;align-content:start;justify-content:start}
  .story-card{background:#161616;border-radius:8px;overflow:hidden;border:1px solid #222;cursor:pointer;width:160px;height:260px;display:flex;flex-direction:column}
  .story-thumb{width:160px;height:200px;object-fit:cover;display:block;flex-shrink:0}
  .story-thumb-video{width:160px;height:200px;object-fit:cover;display:block;flex-shrink:0}
  .story-type-badge{position:absolute;top:5px;left:5px;font-size:0.6rem;padding:2px 5px;border-radius:3px;background:rgba(0,0,0,0.7);color:#fff}
  .story-wrap{position:relative;width:160px;height:200px;flex-shrink:0;overflow:hidden}
  .story-meta{padding:4px 7px;font-size:0.65rem;color:#444;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0}
  .story-open-btn{display:block;width:100%;padding:4px;text-align:center;font-size:0.7rem;color:#a78bfa;background:#1a0f2e;border:none;cursor:pointer;border-top:1px solid #222}
  .story-thumb-placeholder{width:160px;height:200px;display:flex;align-items:center;justify-content:center;font-size:2.5rem;background:#111;color:#444;flex-shrink:0}
  .stories-load-more{grid-column:1/-1;padding:10px;text-align:center}
  .stories-load-more button{padding:7px 24px;background:#1a1a2e;border:1px solid #a78bfa;color:#a78bfa;border-radius:7px;cursor:pointer;font-size:0.8rem}
  .stories-load-more button:hover{background:#2a1f4a}
  .story-btn-row{display:flex;border-top:1px solid #222}
  .story-btn-row a{flex:1;padding:4px;text-align:center;font-size:0.7rem;color:#a78bfa;background:#1a0f2e;text-decoration:none}
  .story-btn-row a+a{border-left:1px solid #222}
  .story-btn-row a:hover{background:#2a1f4a}
  .story-modal{position:fixed;inset:0;background:rgba(0,0,0,0.92);z-index:9000;display:flex;align-items:center;justify-content:center}
  .story-modal-box{display:flex;flex-direction:column;max-width:92vw;max-height:94vh;background:#141414;border:1px solid #2a2a2a;border-radius:10px;overflow:hidden}
  .story-modal-bar{display:flex;align-items:center;gap:10px;padding:8px 12px;background:#1a1a1a;border-bottom:1px solid #222;flex-shrink:0}
  .story-modal-ts{font-size:0.75rem;color:#555;flex:1}
  .story-modal-dl{font-size:0.75rem;color:#38bdf8;text-decoration:none;padding:3px 10px;border:1px solid #1e3a5a;border-radius:5px;background:#0d1a2e}
  .story-modal-dl:hover{background:#1a2e4a}
  .story-modal-close{background:transparent;border:1px solid #333;color:#888;border-radius:5px;padding:3px 8px;cursor:pointer;font-size:0.8rem}
  .story-modal-close:hover{border-color:#f87171;color:#f87171}
  .story-modal-media{display:flex;align-items:center;justify-content:center;min-width:300px;min-height:200px;overflow:auto}
  .story-modal-content{max-width:90vw;max-height:85vh;object-fit:contain;display:block}
  .dl-btn{font-size:0.7rem;padding:2px 7px;border-radius:4px;background:#0d1a2e;color:#38bdf8;text-decoration:none;border:1px solid #1e3a5a;margin-left:4px;display:inline-block;vertical-align:middle}
  .dl-btn:hover{background:#1a2e4a;color:#7dd3fc}

  .placeholder{flex:1;display:flex;align-items:center;justify-content:center;color:#2a2a2a;font-size:0.9rem}
  ::-webkit-scrollbar{width:4px}
  ::-webkit-scrollbar-track{background:transparent}
  ::-webkit-scrollbar-thumb{background:#252525;border-radius:2px}
</style>
</head>
<body>
<header>
  <h1>PurrfectSC Viewer</h1>
  <div class="stats" id="stats">Loading...</div>
</header>
<div class="main">
  <div class="sidebar">
    <div class="sidebar-tabs">
      <div class="sidebar-tab active" id="tabChats" onclick="switchSidebar('chats')">Chats</div>
      <div class="sidebar-tab" id="tabStories" onclick="switchSidebar('stories')">Stories</div>
    </div>
    <div class="search-box">
      <input type="text" id="search" placeholder="Search..." autocomplete="off">
      <button class="sort-btn" id="sortBtn" onclick="toggleSort()" title="Toggle sort order">Recent</button>
    </div>
    <div class="list-pane" id="listPane"></div>
  </div>
  <div class="chat-area" id="chatArea">
    <div class="placeholder">Select a user to view content</div>
  </div>
</div>

<script>
let activeUser = null;
let activeUserId = null;
let activeSidebarMode = 'chats'; // 'chats' | 'stories'
let activeChatTab = 'messages'; // 'messages' | 'stories'
let searchTimer = null;
let sortMode = 'recent'; // 'recent' | 'az'

function toggleSort() {
  sortMode = sortMode === 'recent' ? 'az' : 'recent';
  const btn = document.getElementById('sortBtn');
  btn.textContent = sortMode === 'az' ? 'A–Z' : 'Recent';
  btn.classList.toggle('active-az', sortMode === 'az');
  loadList(document.getElementById('search').value);
}

// ── Stats ────────────────────────────────────────────────────────────────────
async function loadStats() {
  const d = await fetch('/api/stats').then(r=>r.json());
  document.getElementById('stats').textContent =
    `${d.users.toLocaleString()} users · ${d.messages.toLocaleString()} msgs · ${d.stories.toLocaleString()} stories`;
}

// ── Sidebar switching ────────────────────────────────────────────────────────
function switchSidebar(mode) {
  activeSidebarMode = mode;
  document.getElementById('tabChats').classList.toggle('active', mode==='chats');
  document.getElementById('tabStories').classList.toggle('active', mode==='stories');
  document.getElementById('search').value = '';
  document.getElementById('search').placeholder = mode==='chats' ? 'Search username...' : 'Search story users...';
  loadList('');
}

function loadList(q) {
  if (activeSidebarMode === 'chats') loadChatUsers(q);
  else loadStoryUsers(q);
}

// ── Chat users list ──────────────────────────────────────────────────────────
async function loadChatUsers(q='') {
  document.getElementById('listPane').innerHTML = '<div style="padding:16px;color:#444;font-size:0.8rem">Loading…</div>';
  const users = await fetch('/api/users?q='+encodeURIComponent(q)+'&sort='+sortMode).then(r=>r.json());
  const pane = document.getElementById('listPane');
  pane.innerHTML = '';
  if (!users.length) { pane.innerHTML = '<div style="padding:14px;color:#333;font-size:0.78rem">No users found</div>'; return; }
  users.forEach(u => {
    const d = document.createElement('div');
    d.className = 'list-item' + (u.username===activeUser && activeSidebarMode==='chats' ? ' active' : '');
    d.innerHTML = `<div class="item-name">${esc(u.username)}</div>
      <div class="item-meta">${u.msg_count} msgs &middot; ${u.last_ts}</div>`;
    d.onclick = () => openChatUser(u.username);
    pane.appendChild(d);
  });
}

// ── Story users list ─────────────────────────────────────────────────────────
async function loadStoryUsers(q='') {
  document.getElementById('listPane').innerHTML = '<div style="padding:16px;color:#444;font-size:0.8rem">Loading…</div>';
  const users = await fetch('/api/story-users?q='+encodeURIComponent(q)+'&sort='+sortMode).then(r=>r.json());
  const pane = document.getElementById('listPane');
  pane.innerHTML = '';
  if (!users.length) { pane.innerHTML = '<div style="padding:14px;color:#333;font-size:0.78rem">No story users found</div>'; return; }
  users.forEach(u => {
    const d = document.createElement('div');
    d.className = 'list-item' + (u.user_id===activeUserId && activeSidebarMode==='stories' ? ' active' : '');
    d.innerHTML = `<div class="item-name ${u.has_username?'':'no-username'}">${esc(u.display)}</div>
      <div class="item-meta">${u.story_count} stories &middot; ${u.last_ts}</div>`;
    d.onclick = () => openStoryUser(u.user_id, u.display);
    pane.appendChild(d);
  });
}

// ── Open chat user ───────────────────────────────────────────────────────────
async function openChatUser(username) {
  activeUser = username;
  activeChatTab = 'messages';
  highlightActive(username, null);
  const area = document.getElementById('chatArea');
  area.innerHTML = `
    <div class="chat-header">
      <span class="chat-username">${esc(username)}</span>
      <div class="chat-tabs">
        <button class="tab-btn active" onclick="switchChatTab('messages',this)">Messages</button>
        <button class="tab-btn" onclick="switchChatTab('stories',this)">Stories</button>
      </div>
    </div>
    <div class="msg-search-bar" id="msgSearchBar">
      <input type="text" id="msgSearch" placeholder="Search in conversation…" autocomplete="off" oninput="filterMessages(this.value)">
      <button class="nav-btn" id="prevMatch" onclick="stepMatch(-1)" style="display:none">▲</button>
      <button class="nav-btn" id="nextMatch" onclick="stepMatch(1)" style="display:none">▼</button>
      <span class="msg-search-count" id="msgSearchCount"></span>
    </div>
    <div id="contentPane"></div>`;
  showLoading('Loading messages\u2026');
  setTimeout(() => loadMessages(username), 0);
}

// ── Open story user (from stories sidebar) ───────────────────────────────────
function openStoryUser(userId, displayName) {
  activeUserId = userId;
  highlightActive(null, userId);
  const area = document.getElementById('chatArea');
  area.innerHTML = `
    <div class="chat-header">
      <span class="chat-username">${esc(displayName)}</span>
      <span class="chat-sub">stories</span>
    </div>
    <div id="contentPane"></div>`;
  showLoading('Loading stories\u2026');
  setTimeout(() => loadStoriesById(userId), 0);
}

function highlightActive(username, userId) {
  document.querySelectorAll('.list-item').forEach(el => {
    const nameEl = el.querySelector('.item-name');
    if (!nameEl) return;
    const txt = nameEl.textContent;
    el.classList.toggle('active',
      (username && txt === username) || (userId && el.dataset.uid === userId));
  });
}

// ── Chat tab switching ───────────────────────────────────────────────────────
function switchChatTab(tab, btn) {
  activeChatTab = tab;
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  const pane = document.getElementById('contentPane');
  const bar = document.getElementById('msgSearchBar');
  const searchEl = document.getElementById('msgSearch');
  const countEl = document.getElementById('msgSearchCount');
  if (bar) bar.style.display = '';
  if (searchEl) {
    searchEl.value = '';
    _matchEls = []; _matchIdx = -1;
    const prevBtn = document.getElementById('prevMatch');
    const nextBtn = document.getElementById('nextMatch');
    if (prevBtn) prevBtn.style.display = 'none';
    if (nextBtn) nextBtn.style.display = 'none';
    searchEl.placeholder = tab === 'messages' ? 'Search in conversation…' : 'Filter stories by date…';
    searchEl.oninput = tab === 'messages'
      ? () => filterMessages(searchEl.value)
      : () => filterStories(searchEl.value);
  }
  if (countEl) countEl.textContent = '';
  showLoading(tab==='messages' ? 'Loading messages\u2026' : 'Loading stories\u2026', pane);
  setTimeout(() => {
    if (tab==='messages') {
      loadMessages(activeUser);
    } else {
      fetch('/api/user-id/'+encodeURIComponent(activeUser))
        .then(r=>r.json())
        .then(d => {
          if (d.user_id) loadStoriesById(d.user_id);
          else { hideLoading(); pane.className='messages'; pane.innerHTML='<div style="color:#444;padding:20px">No stories for this user</div>'; }
        });
    }
  }, 0);

}

// ── Load messages ────────────────────────────────────────────────────────────
const TYPE_LABELS = {
  STATUS_CALL_MISSED_AUDIO: 'Missed audio call',
  STATUS_CALL_MISSED_VIDEO: 'Missed video call',
  STATUS_CONVERSATION_CAPTURE_SCREENSHOT: 'Screenshot taken',
  STATUS_SAVE_TO_CAMERA_ROLL: 'Saved to camera roll',
  STATUS_SNAP_REMIX_CAPTURE: 'Remix captured',
  EXTERNAL_MEDIA: 'MEDIA',
  SNAP: 'SNAP',
  CHAT: 'CHAT',
  NOTE: 'NOTE',
  STICKER: 'STICKER',
  SHARE: 'SHARE',
};

let ownerUsername = null;

function showLoading(label) {
  let ov = document.getElementById('globalLoader');
  if (!ov) {
    ov = document.createElement('div');
    ov.id = 'globalLoader';
    ov.style.cssText = [
      'position:fixed','top:50%','left:50%',
      'transform:translate(-50%,-50%)',
      'background:#1a1a2e','border:1px solid #a78bfa',
      'border-radius:12px','padding:18px 28px',
      'z-index:9999','display:flex','align-items:center','gap:12px',
      'box-shadow:0 4px 32px rgba(0,0,0,.6)'
    ].join(';');
    document.body.appendChild(ov);
  }
  ov.innerHTML = '<div style="width:22px;height:22px;border:3px solid #333;border-top-color:#a78bfa;border-radius:50%;animation:spin .7s linear infinite;flex-shrink:0"></div>'
    + '<span style="color:#a78bfa;font-size:0.85rem">' + (label||'Loading\u2026') + '</span>';
  ov.style.display = 'flex';
}

function hideLoading() {
  const ov = document.getElementById('globalLoader');
  if (ov) ov.style.display = 'none';
}

async function ensureOwner() {
  if (!ownerUsername) {
    const d = await fetch('/api/owner').then(r=>r.json());
    ownerUsername = d.username;
  }
}

async function loadMessages(username) {
  await ensureOwner();
  const msgs = await fetch('/api/conversation/'+encodeURIComponent(username)).then(r=>r.json());
  hideLoading();
  const pane = document.getElementById('contentPane');
  if (!msgs.length) { pane.style.cssText=''; pane.className='messages'; pane.innerHTML = '<div style="color:#333;padding:20px">No messages</div>'; return; }

  let lastConvId = null;
  let html = '';

  msgs.forEach(m => {
    const isStatus = m.type.startsWith('STATUS_');
    const pillClass = isStatus ? 'pill-STATUS' : ('pill-' + m.type);
    const label = TYPE_LABELS[m.type] || m.type;

    // Conversation separator when conv_id changes
    if (m.conv_id !== lastConvId) {
      if (lastConvId !== null) html += `<div class="conv-sep">─── new conversation ───</div>`;
      lastConvId = m.conv_id;
    }

    const badges = [
      m.deleted   ? '<span class="badge b-deleted">deleted</span>' : '',
      m.edited    ? '<span class="badge b-edited">edited</span>'   : '',
      m.saved     ? '<span class="badge b-saved">saved</span>'     : '',
      m.screenshot? '<span class="badge b-shot">screenshot</span>' : '',
      m.has_audio ? '<span class="badge b-audio">audio</span>'     : '',
    ].join('');

    let bodyHtml = '';
    if (m.text) {
      bodyHtml = `<span class="msg-text">${esc(m.text)}</span>`;
    } else if ((m.type==='SNAP'||m.type==='EXTERNAL_MEDIA') && m.snap_keys && m.snap_keys.length) {
      bodyHtml = m.snap_keys.map(k=>`<span class="snap-key">${esc(k)}</span>`).join('');
      bodyHtml += ` <a class="dl-btn" href="/api/snap-download/${m.id}" download title="Download snap">⬇ Download</a>`;
    } else if ((m.type==='SNAP'||m.type==='EXTERNAL_MEDIA') && !m.text) {
      bodyHtml = `<a class="dl-btn" href="/api/snap-download/${m.id}" download title="Download snap">⬇ Download</a>`;
    } else if (isStatus) {
      bodyHtml = `<span style="color:#333;font-size:0.73rem;font-style:italic">${esc(label)}</span>`;
    } else {
      bodyHtml = '';
    }

    if (isStatus) {
      html += `<div class="msg-row status-row">
        <div class="msg-bubble">
          <span class="type-pill pill-STATUS">${esc(label)}</span>
          ${badges}${bodyHtml}
          <span class="msg-ts" style="margin-left:4px">${m.ts}</span>
        </div>
      </div>`;
    } else {
      const side = m.is_me ? 'me' : 'them';
      const senderLabel = m.is_me ? 'You' : esc(m.sender);
      html += `<div class="msg-row ${side}">
        <div class="msg-sender">${senderLabel}</div>
        <div class="msg-bubble">
          <span class="type-pill ${pillClass}">${label}</span>${badges}
          ${bodyHtml}
        </div>
        <div class="msg-meta"><span class="msg-ts">${m.ts}</span></div>
      </div>`;
    }
  });

  pane.style.cssText = '';
  pane.className = 'messages';
  pane.innerHTML = html;
  pane.scrollTop = pane.scrollHeight;
}

let _matchEls = [];
let _matchIdx = -1;

function filterMessages(q) {
  const pane = document.getElementById('contentPane');
  const countEl = document.getElementById('msgSearchCount');
  const prevBtn = document.getElementById('prevMatch');
  const nextBtn = document.getElementById('nextMatch');

  // Clear previous highlights
  pane.querySelectorAll('.msg-row').forEach(r => restoreHighlights(r));
  _matchEls = [];
  _matchIdx = -1;

  if (!q.trim()) {
    if (countEl) countEl.textContent = '';
    if (prevBtn) prevBtn.style.display = 'none';
    if (nextBtn) nextBtn.style.display = 'none';
    return;
  }

  const re = new RegExp(escRe(q), 'gi');
  pane.querySelectorAll('.msg-text').forEach(textEl => {
    const orig = textEl.textContent;
    if (!orig.toLowerCase().includes(q.toLowerCase())) return;
    textEl.innerHTML = orig.replace(re, m => `<mark class="highlight">${esc(m)}</mark>`);
    textEl.querySelectorAll('.highlight').forEach(el => _matchEls.push(el));
  });

  const count = _matchEls.length;
  if (countEl) countEl.textContent = count ? `1 / ${count}` : 'No results';
  if (prevBtn) prevBtn.style.display = count ? '' : 'none';
  if (nextBtn) nextBtn.style.display = count ? '' : 'none';

  if (count) { _matchIdx = 0; scrollToMatch(); }
}

function stepMatch(dir) {
  if (!_matchEls.length) return;
  _matchIdx = (_matchIdx + dir + _matchEls.length) % _matchEls.length;
  scrollToMatch();
  const countEl = document.getElementById('msgSearchCount');
  if (countEl) countEl.textContent = `${_matchIdx + 1} / ${_matchEls.length}`;
}

function scrollToMatch() {
  _matchEls.forEach((el, i) => el.classList.toggle('active-match', i === _matchIdx));
  const active = _matchEls[_matchIdx];
  if (!active) return;
  const pane = document.getElementById('contentPane');
  const paneTop = pane.getBoundingClientRect().top;
  const elTop   = active.getBoundingClientRect().top;
  pane.scrollTop += elTop - paneTop - (pane.clientHeight / 2);
}

function filterStories(q) {
  const pane = document.getElementById('contentPane');
  const countEl = document.getElementById('msgSearchCount');
  const cards = pane.querySelectorAll('.story-card');
  if (!q.trim()) {
    cards.forEach(c => c.style.display = '');
    if (countEl) countEl.textContent = '';
    return;
  }
  const lower = q.toLowerCase();
  let matches = 0;
  cards.forEach(card => {
    const meta = card.querySelector('.story-meta');
    const text = meta ? meta.textContent.toLowerCase() : '';
    const visible = text.includes(lower);
    card.style.display = visible ? '' : 'none';
    if (visible) matches++;
  });
  if (countEl) countEl.textContent = matches ? `${matches} result${matches>1?'s':''}` : 'No results';
}

function restoreHighlights(row) {
  const marks = row.querySelectorAll('mark.highlight');
  marks.forEach(m => m.replaceWith(document.createTextNode(m.textContent)));
}

function escRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ── Load stories by user_id ──────────────────────────────────────────────────
const STORIES_PAGE = 50;

async function loadStoriesById(userId) {
  const stories = await fetch('/api/stories/'+encodeURIComponent(userId)).then(r=>r.json());
  hideLoading();
  const pane = document.getElementById('contentPane');
  if (!stories.length) { pane.style.cssText=''; pane.className='messages'; pane.innerHTML='<div style="color:#444;padding:20px">No stories</div>'; return; }

  pane.style.cssText = '';
  pane.className = 'stories-grid';
  window._currentStories = stories;
  window._currentStoriesUserId = userId;
  window._storiesOffset = 0;
  pane.innerHTML = '';
  renderStoryPage(pane);
}

function storyCardHtml(s, i) {
  const userId = window._currentStoriesUserId;
  const proxyUrl = `/api/story-download?url=${encodeURIComponent(s.url)}&user_id=${encodeURIComponent(userId)}&ts=${encodeURIComponent(s.posted||s.added)}`;
  const typeIcon = s.is_video ? '▶' : '🖼';
  return `<div class="story-card" onclick="openStoryViewer(${i})">
    <div class="story-wrap">
      <div class="story-thumb-placeholder">${typeIcon}</div>
      <span class="story-type-badge">${s.is_video ? '▶ Video' : '🖼 Image'}</span>
    </div>
    <div class="story-meta">${esc(s.posted||s.added)}</div>
    <div class="story-btn-row" onclick="event.stopPropagation()">
      <a href="${proxyUrl}" download>⬇ Save</a>
    </div>
  </div>`;
}

function renderStoryPage(pane) {
  const stories = window._currentStories;
  const offset = window._storiesOffset;
  const slice = stories.slice(offset, offset + STORIES_PAGE);

  // Remove old load-more button if present
  const old = pane.querySelector('.stories-load-more');
  if (old) old.remove();

  pane.insertAdjacentHTML('beforeend', slice.map((s, j) => storyCardHtml(s, offset + j)).join(''));
  window._storiesOffset += slice.length;

  if (window._storiesOffset < stories.length) {
    const remaining = stories.length - window._storiesOffset;
    pane.insertAdjacentHTML('beforeend',
      `<div class="stories-load-more"><button onclick="renderStoryPage(document.getElementById('contentPane'))">Load ${Math.min(remaining, STORIES_PAGE)} more (${remaining} left)</button></div>`);
  }
}

function openStoryViewer(idx) {
  const s = window._currentStories[idx];
  const userId = window._currentStoriesUserId;
  if (!s) return;
  const url = s.url, isVideo = s.is_video, ts = s.posted || s.added;
  const proxyUrl = `/api/story-download?url=${encodeURIComponent(url)}&user_id=${encodeURIComponent(userId)}&ts=${encodeURIComponent(ts)}`;
  let modal = document.getElementById('storyModal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'storyModal';
    document.body.appendChild(modal);
  }
  modal.className = 'story-modal';
  modal.onclick = e => { if (e.target === modal) closeStoryViewer(); };
  modal.innerHTML = `
    <div class="story-modal-box">
      <div class="story-modal-bar">
        <span class="story-modal-ts">${esc(ts)}</span>
        <a class="story-modal-dl" href="${proxyUrl}" download>⬇ Save</a>
        <button class="story-modal-close" onclick="closeStoryViewer()">✕</button>
      </div>
      <div class="story-modal-media" id="storyModalMedia">
        <div class="spinner"></div>
      </div>
    </div>`;
  modal.style.display = 'flex';

  const container = document.getElementById('storyModalMedia');
  if (isVideo) {
    const v = document.createElement('video');
    v.src = proxyUrl; v.controls = true; v.autoplay = true;
    v.className = 'story-modal-content';
    v.oncanplay = () => { const sp = container.querySelector('.spinner'); if(sp) sp.remove(); };
    v.onerror = () => { container.innerHTML = '<span style="color:#f87171;padding:20px">Failed to load — server may be offline</span>'; };
    container.appendChild(v);
  } else {
    const img = document.createElement('img');
    img.src = proxyUrl;
    img.className = 'story-modal-content';
    img.onload = () => { const sp = container.querySelector('.spinner'); if(sp) sp.remove(); };
    img.onerror = () => { container.innerHTML = '<span style="color:#f87171;padding:20px">Failed to load — server may be offline</span>'; };
    container.appendChild(img);
  }
}

function closeStoryViewer() {
  const modal = document.getElementById('storyModal');
  if (!modal) return;
  modal.querySelectorAll('video').forEach(v => { v.pause(); v.src = ''; });
  modal.style.display = 'none';
  modal.innerHTML = '';
}

// ── Search ───────────────────────────────────────────────────────────────────
document.getElementById('search').addEventListener('input', e => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => loadList(e.target.value), 220);
});

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Init
loadStats();
loadList('');
</script>
</body>
</html>"""

if __name__ == "__main__":
    app.run(debug=True, port=5000)
