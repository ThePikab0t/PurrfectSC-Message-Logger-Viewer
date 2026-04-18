import sqlite3
import json
import re
from datetime import datetime
from flask import Flask, jsonify, request, render_template_string

app = Flask(__name__)
DB_PATH = "/home/hack3r/Web/PurrfectSC/message_loggerr.db"

VIDEO_PREFIXES = {"/4/", "/3/", "/u/"}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


_SYSTEM_STRINGS = {
    "CHAT", "SNAP", "EXTERNAL_MEDIA", "NOTE", "STICKER", "SHARE",
    "UNKNOWN", "NONE", "NORMAL", "STATUS", "OPEN", "CLOSED",
    "TRUE", "FALSE", "NULL", "SAVE_POLICY", "ERASABLE", "SAVEABLE",
}


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
    conn = get_db()
    cur = conn.cursor()
    if q:
        cur.execute(
            """SELECT username, COUNT(*) as msg_count, MAX(send_timestamp) as last_ts
               FROM messages WHERE lower(username) LIKE ?
               GROUP BY username ORDER BY last_ts DESC LIMIT 100""",
            (f"%{q}%",),
        )
    else:
        cur.execute(
            """SELECT username, COUNT(*) as msg_count, MAX(send_timestamp) as last_ts
               FROM messages GROUP BY username ORDER BY last_ts DESC LIMIT 200"""
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
    conn = get_db()
    cur = conn.cursor()
    # Use subquery to avoid COUNT(*) inflation from the LEFT JOIN
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
            base + " HAVING lower(COALESCE(username, s.user_id)) LIKE ? ORDER BY last_ts DESC LIMIT 100",
            (f"%{q}%",),
        )
    else:
        cur.execute(base + " ORDER BY last_ts DESC LIMIT 200")
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
  .search-box{padding:8px 10px;border-bottom:1px solid #1e1e1e}
  .search-box input{width:100%;padding:7px 11px;background:#1a1a1a;border:1px solid #2a2a2a;border-radius:7px;color:#e0e0e0;font-size:0.82rem;outline:none}
  .search-box input:focus{border-color:#a78bfa}
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
  .messages{flex:1;overflow-y:auto;padding:14px 16px;display:flex;flex-direction:column;gap:3px}
  .msg{display:flex;gap:10px;align-items:flex-start;padding:3px 5px;border-radius:5px}
  .msg:hover{background:#161616}
  .msg-ts{font-size:0.66rem;color:#383838;white-space:nowrap;padding-top:3px;min-width:105px}
  .msg-body{flex:1}
  .type-pill{display:inline-block;font-size:0.62rem;padding:1px 5px;border-radius:4px;margin-right:4px;vertical-align:middle;font-weight:600}
  .pill-CHAT{background:#0d2b1a;color:#4ade80}
  .pill-SNAP{background:#0d1f2e;color:#38bdf8}
  .pill-EXTERNAL_MEDIA{background:#1e1030;color:#c084fc}
  .pill-NOTE{background:#2a2310;color:#fbbf24}
  .pill-STICKER{background:#0d2222;color:#34d399}
  .pill-SHARE{background:#2a1010;color:#f87171}
  .pill-STATUS{background:#1a1a1a;color:#555}
  .pill-UNKNOWN{background:#1a1a1a;color:#333}
  .msg-text{font-size:0.84rem;color:#d0d0d0;word-break:break-word}
  .snap-key{font-size:0.65rem;color:#1e6a9e;font-family:monospace;background:#0d1520;padding:1px 5px;border-radius:3px;margin-right:3px;display:inline-block}
  .badge{font-size:0.58rem;padding:1px 4px;border-radius:3px;margin-left:2px;vertical-align:middle}
  .b-edited{background:#2a2308;color:#fbbf24}
  .b-deleted{background:#2a0d0d;color:#f87171}
  .b-saved{background:#0d1a2a;color:#60a5fa}
  .b-shot{background:#2a0d1a;color:#f472b6}
  .b-audio{background:#1a1a0d;color:#a3e635}

  /* Stories grid */
  .stories-grid{flex:1;overflow-y:auto;padding:14px;display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;align-content:start}
  .story-card{background:#161616;border-radius:8px;overflow:hidden;border:1px solid #222;cursor:pointer}
  .story-thumb{width:100%;height:150px;object-fit:cover;display:block;background:#1a1a1a}
  .story-thumb-video{width:100%;height:150px;object-fit:cover;display:block;background:#0d1520}
  .story-type-badge{position:absolute;top:5px;left:5px;font-size:0.6rem;padding:2px 5px;border-radius:3px;background:rgba(0,0,0,0.7);color:#fff}
  .story-wrap{position:relative}
  .story-meta{padding:5px 7px;font-size:0.65rem;color:#444}
  .story-open-btn{display:block;width:100%;padding:4px;text-align:center;font-size:0.7rem;color:#a78bfa;background:#1a0f2e;border:none;cursor:pointer;border-top:1px solid #222}

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
    <div class="search-box"><input type="text" id="search" placeholder="Search..." autocomplete="off"></div>
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
  const users = await fetch('/api/users?q='+encodeURIComponent(q)).then(r=>r.json());
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
  const users = await fetch('/api/story-users?q='+encodeURIComponent(q)).then(r=>r.json());
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
    <div id="contentPane" class="messages"><div style="color:#333;padding:20px">Loading…</div></div>`;
  loadMessages(username);
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
    <div id="contentPane" class="stories-grid"><div style="color:#333;padding:20px">Loading…</div></div>`;
  loadStoriesById(userId);
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
  pane.className = tab==='stories' ? 'stories-grid' : 'messages';
  pane.innerHTML = '<div style="color:#333;padding:20px">Loading…</div>';
  if (tab==='messages') loadMessages(activeUser);
  else {
    // Need to resolve username -> user_id for stories
    fetch('/api/users?q='+encodeURIComponent(activeUser)).then(r=>r.json()).then(users => {
      // Find exact match then use user_id via story-users
      fetch('/api/story-users?q='+encodeURIComponent(activeUser)).then(r=>r.json()).then(list => {
        const found = list.find(u => u.display === activeUser || u.has_username && u.display === activeUser);
        if (found) loadStoriesById(found.user_id);
        else { pane.innerHTML = '<div style="color:#444;padding:20px">No stories for this user</div>'; }
      });
    });
  }
}

// ── Load messages ────────────────────────────────────────────────────────────
const TYPE_LABELS = {
  STATUS_CALL_MISSED_AUDIO: 'MISSED CALL',
  STATUS_CALL_MISSED_VIDEO: 'MISSED VIDEO CALL',
  STATUS_CONVERSATION_CAPTURE_SCREENSHOT: 'SCREENSHOT TAKEN',
  STATUS_SAVE_TO_CAMERA_ROLL: 'SAVED TO CAMERA ROLL',
  STATUS_SNAP_REMIX_CAPTURE: 'REMIX CAPTURE',
  EXTERNAL_MEDIA: 'MEDIA',
  SNAP: 'SNAP',
  CHAT: 'CHAT',
  NOTE: 'NOTE',
  STICKER: 'STICKER',
  SHARE: 'SHARE',
};

async function loadMessages(username) {
  const msgs = await fetch('/api/conversation/'+encodeURIComponent(username)).then(r=>r.json());
  const pane = document.getElementById('contentPane');
  if (!msgs.length) { pane.innerHTML = '<div style="color:#333;padding:20px">No messages</div>'; return; }

  pane.innerHTML = msgs.map(m => {
    const isStatus = m.type.startsWith('STATUS_');
    const pillClass = isStatus ? 'pill-STATUS' : ('pill-' + m.type);
    const label = TYPE_LABELS[m.type] || m.type;

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
      bodyHtml = m.snap_keys.map(k=>`<span class="snap-key" title="Media key">${esc(k)}</span>`).join('');
      bodyHtml += `<span style="color:#1e6a9e;font-size:0.72rem">${m.type==='SNAP'?'(snap photo/video)':'(external media)'}</span>`;
    } else if (isStatus) {
      bodyHtml = `<span style="color:#333;font-size:0.75rem;font-style:italic">${label}</span>`;
    } else {
      bodyHtml = `<span style="color:#2a2a2a;font-size:0.73rem">${label}</span>`;
    }

    return `<div class="msg">
      <span class="msg-ts">${m.ts}</span>
      <div class="msg-body">
        <span class="type-pill ${pillClass}">${label}</span>${badges}
        ${bodyHtml}
      </div>
    </div>`;
  }).join('');

  pane.scrollTop = pane.scrollHeight;
}

// ── Load stories by user_id ──────────────────────────────────────────────────
async function loadStoriesById(userId) {
  const stories = await fetch('/api/stories/'+encodeURIComponent(userId)).then(r=>r.json());
  const pane = document.getElementById('contentPane');
  if (!stories.length) { pane.innerHTML = '<div style="color:#444;padding:20px">No stories</div>'; return; }

  pane.innerHTML = stories.map(s => {
    const mediaEl = s.is_video
      ? `<video class="story-thumb-video" src="${esc(s.url)}" preload="metadata" muted></video>`
      : `<img class="story-thumb" src="${esc(s.url)}" loading="lazy" onerror="this.style.opacity='0.1'">`;
    return `<div class="story-card">
      <div class="story-wrap">
        <a href="${esc(s.url)}" target="_blank" rel="noopener">${mediaEl}</a>
        <span class="story-type-badge">${s.is_video ? '▶ Video' : '🖼 Image'}</span>
      </div>
      <div class="story-meta">${s.posted||s.added}</div>
      <a href="${esc(s.url)}" target="_blank" rel="noopener" class="story-open-btn">Open</a>
    </div>`;
  }).join('');
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
