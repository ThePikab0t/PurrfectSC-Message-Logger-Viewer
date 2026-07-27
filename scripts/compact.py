"""Compact a bloated message-logger export.

The backup app pre-reserves a ~944 MB file even when it holds little data, so a
fresh export is mostly empty space. VACUUM rebuilds it compactly with zero data
loss (verified by row-count + integrity check).

Usage:
    python scripts/compact.py <export.db> [output.db]

If output.db is omitted, the file is compacted in place (via a temp copy).
"""
import sqlite3
import os
import sys

TABLES = ["messages", "stories", "tracker_events", "chat_edits", "android_metadata"]


def counts(path):
    con = sqlite3.connect(path)
    try:
        present = {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        return {t: con.execute("SELECT COUNT(*) FROM %s" % t).fetchone()[0]
                for t in TABLES if t in present}
    finally:
        con.close()


def integrity(path):
    con = sqlite3.connect(path)
    try:
        return con.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        con.close()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else src
    in_place = os.path.abspath(src) == os.path.abspath(dst)
    tmp = dst + ".tmp" if in_place else dst
    if os.path.exists(tmp):
        os.remove(tmp)

    before = counts(src)
    con = sqlite3.connect(src)
    con.execute("VACUUM INTO ?", (tmp.replace("\\", "/"),))
    con.close()

    after = counts(tmp)
    integ = integrity(tmp)
    if before != after or integ != "ok":
        print("VERIFY FAILED — original left untouched.")
        print("  before:", before)
        print("  after :", after, "integrity:", integ)
        os.remove(tmp)
        sys.exit(2)

    so, co = os.path.getsize(src), os.path.getsize(tmp)
    if in_place:
        os.remove(src)
        os.rename(tmp, dst)
    print("OK  %.0f MB -> %.0f MB (%.1fx smaller)  messages=%s  integrity=%s"
          % (so / 1e6, co / 1e6, so / max(co, 1), before.get("messages"), integ))


if __name__ == "__main__":
    main()
