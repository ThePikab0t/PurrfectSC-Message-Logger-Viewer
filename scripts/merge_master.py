"""Rebuild the merged master archive from every export in DBs/.

Scans DBs/*.db (top level only; DBs/archive/ is ignored), merges all rows, and
writes a single compact DBs/message_logger_master.db, deduplicated by each
table's real identity key:

    messages   -> message_id            (Snapchat message id)
    stories    -> url                   (CDN media url; stories.id is only a
                                          per-file row number, NOT an identity)
    chat_edits -> (message_id, edit_number, message_text)

The local `id` PRIMARY KEY column is dropped and reassigned so ids from
different files don't collide. Runs VACUUM + integrity_check at the end.

Usage:
    python scripts/merge_master.py
"""
import sqlite3
import os
import glob

DBDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "DBs")
DBDIR = os.path.abspath(DBDIR)
MASTER = os.path.join(DBDIR, "message_logger_master.db")

DDL = {
    "android_metadata": "CREATE TABLE android_metadata (locale TEXT)",
    "chat_edits": "CREATE TABLE chat_edits (id INTEGER PRIMARY KEY, edit_number INTEGER, added_timestamp BIGINT, conversation_id VARCHAR, message_id BIGINT, message_text BLOB)",
    "messages": "CREATE TABLE messages (id INTEGER PRIMARY KEY, message_id BIGINT, conversation_id VARCHAR, user_id CHAR(36), username VARCHAR, send_timestamp BIGINT, added_timestamp BIGINT, group_title VARCHAR, message_data BLOB)",
    "stories": "CREATE TABLE stories (id INTEGER PRIMARY KEY, added_timestamp BIGINT, user_id VARCHAR, posted_timestamp BIGINT, created_timestamp BIGINT, url VARCHAR, encryption_key BLOB, encryption_iv BLOB)",
    "tracker_events": "CREATE TABLE tracker_events (id INTEGER PRIMARY KEY, timestamp BIGINT, conversation_id CHAR(36), conversation_title VARCHAR, is_group BOOLEAN, username VARCHAR, user_id VARCHAR, event_type VARCHAR, data VARCHAR)",
}

# table -> (columns to copy, unique dedup index, insert order)
COPY = {
    "messages": (
        "message_id, conversation_id, user_id, username, send_timestamp, added_timestamp, group_title, message_data",
        "CREATE UNIQUE INDEX ux_msg ON messages(message_id)",
        "ORDER BY send_timestamp",
    ),
    "stories": (
        "added_timestamp, user_id, posted_timestamp, created_timestamp, url, encryption_key, encryption_iv",
        "CREATE UNIQUE INDEX ux_story ON stories(url)",
        "ORDER BY posted_timestamp",
    ),
    "chat_edits": (
        "edit_number, added_timestamp, conversation_id, message_id, message_text",
        "CREATE UNIQUE INDEX ux_edit ON chat_edits(message_id, edit_number, message_text)",
        "ORDER BY added_timestamp",
    ),
}


def main():
    sources = sorted(p for p in glob.glob(os.path.join(DBDIR, "*.db"))
                     if os.path.abspath(p) != os.path.abspath(MASTER))
    if not sources:
        print("No source .db files found in", DBDIR)
        return
    print("Merging %d file(s):" % len(sources))
    for s in sources:
        print("  -", os.path.basename(s))

    if os.path.exists(MASTER):
        os.remove(MASTER)
    m = sqlite3.connect(MASTER)
    mc = m.cursor()
    for ddl in DDL.values():
        mc.execute(ddl)
    for _, idx, _ in COPY.values():
        mc.execute(idx)
    m.commit()

    loc = sqlite3.connect(sources[0]).execute(
        "SELECT locale FROM android_metadata LIMIT 1").fetchone()
    if loc:
        mc.execute("INSERT INTO android_metadata(locale) VALUES(?)", (loc[0],))
    m.commit()

    for src in sources:
        m.execute("ATTACH DATABASE ? AS src", (src.replace("\\", "/"),))
        for t, (cols, _, order) in COPY.items():
            m.execute("INSERT OR IGNORE INTO %s (%s) SELECT %s FROM src.%s %s"
                      % (t, cols, cols, t, order))
        m.commit()
        m.execute("DETACH DATABASE src")

    for name in ("ux_msg", "ux_story", "ux_edit"):
        mc.execute("DROP INDEX IF EXISTS %s" % name)
    m.commit()
    mc.execute("VACUUM")
    m.commit()

    cnt = {t: mc.execute("SELECT COUNT(*) FROM %s" % t).fetchone()[0]
           for t in ("messages", "stories", "chat_edits", "tracker_events")}
    integ = mc.execute("PRAGMA integrity_check").fetchone()[0]
    m.close()
    print("\nMASTER: %.0f MB  messages=%s stories=%s chat_edits=%s tracker=%s  integrity=%s"
          % (os.path.getsize(MASTER) / 1e6, f"{cnt['messages']:,}", f"{cnt['stories']:,}",
             cnt["chat_edits"], cnt["tracker_events"], integ))


if __name__ == "__main__":
    main()
