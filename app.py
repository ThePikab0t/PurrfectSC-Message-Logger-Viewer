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
async function loadStoriesById(userId) {
  const stories = await fetch('/api/stories/'+encodeURIComponent(userId)).then(r=>r.json());
  hideLoading();
  const pane = document.getElementById('contentPane');
  if (!stories.length) { pane.style.cssText=''; pane.className='messages'; pane.innerHTML = '<div style="color:#444;padding:20px">No stories</div>'; return; }

  pane.style.cssText = '';
  pane.className = 'stories-grid';
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
