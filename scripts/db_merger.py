"""DB Merger — combine two message-logger database files into one.

Takes two SQLite exports from the message-logger app and merges them into a
single output file (name chosen by you), with NO structure changes and NO data
loss. Rows are de-duplicated by their real identity key:

    messages   -> message_id
    stories    -> url
    chat_edits -> (message_id, edit_number, message_text)
    other tables -> all columns (minus the local id)

How it works: the larger input is copied byte-for-byte to become the output
base (so tables, indexes and triggers stay exactly as the app made them), then
only the rows missing from it are inserted from the other file. Finally it runs
VACUUM + integrity_check and verifies every message from both inputs is present.

The output stays small enough to import back into the app (it never merges more
than you give it), unlike the full master archive which would exceed the app's
size cap.

Usage:
    python scripts/db_merger.py <db_a> <db_b> <output_name.db> [--force]

Example:
    python scripts/db_merger.py dbs/latest.db dbs/new.db dbs/combined.db
"""
import argparse
import os
import shutil
import sqlite3
import sys

# Real identity key per table; tables not listed fall back to "all non-id columns".
NATURAL_KEYS = {
    "messages": ["message_id"],
    "stories": ["url"],
    "chat_edits": ["message_id", "edit_number", "message_text"],
}


def tables(con):
    return {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}


def non_id_columns(con, table):
    return [r[1] for r in con.execute("PRAGMA table_info(%s)" % table) if r[1] != "id"]


def key_expr(cols):
    # quote() gives a consistent, NULL/BLOB-safe text form for building a dedup key
    return " || '|' || ".join("quote(%s)" % c for c in cols)


def message_ids(path):
    con = sqlite3.connect(path)
    try:
        if "messages" in tables(con):
            return {r[0] for r in con.execute("SELECT message_id FROM messages")}
        return set()
    finally:
        con.close()


def main():
    ap = argparse.ArgumentParser(description="Merge two message-logger DB files into one.")
    ap.add_argument("db_a")
    ap.add_argument("db_b")
    ap.add_argument("output", help="name/path of the merged file to create")
    ap.add_argument("--force", action="store_true", help="overwrite output if it exists")
    args = ap.parse_args()

    for p in (args.db_a, args.db_b):
        if not os.path.isfile(p):
            sys.exit("ERROR: input not found: %s" % p)
    if os.path.exists(args.output) and not args.force:
        sys.exit("ERROR: output '%s' already exists. Pick another name or pass --force." % args.output)

    # schema sanity: the two files should come from the same app
    ca, cb = sqlite3.connect(args.db_a), sqlite3.connect(args.db_b)
    ta, tb = tables(ca), tables(cb)
    common = ta & tb
    if ta != tb:
        print("WARNING: table sets differ. Merging only the shared tables: %s" % sorted(common))
    # pick the larger file (by message count) as the structure-preserving base
    na = ca.execute("SELECT COUNT(*) FROM messages").fetchone()[0] if "messages" in ta else 0
    nb = cb.execute("SELECT COUNT(*) FROM messages").fetchone()[0] if "messages" in tb else 0
    ca.close(); cb.close()
    base, other = (args.db_a, args.db_b) if na >= nb else (args.db_b, args.db_a)
    print("base (copied whole): %s   adding missing rows from: %s"
          % (os.path.basename(base), os.path.basename(other)))

    expected = message_ids(args.db_a) | message_ids(args.db_b)

    if os.path.exists(args.output):
        os.remove(args.output)
    shutil.copy2(base, args.output)

    con = sqlite3.connect(args.output)
    con.execute("ATTACH DATABASE ? AS src", (os.path.abspath(other).replace("\\", "/"),))
    for t in sorted(common):
        cols = non_id_columns(con, t)
        if not cols:
            continue
        keycols = NATURAL_KEYS.get(t, cols)
        keycols = [c for c in keycols if c in cols] or cols
        kexpr = key_expr(keycols)
        collist = ", ".join(cols)
        con.execute(
            "INSERT INTO %s (%s) SELECT %s FROM src.%s WHERE (%s) NOT IN (SELECT %s FROM main.%s)"
            % (t, collist, collist, t, kexpr, kexpr, t)
        )
    con.commit()
    con.execute("DETACH DATABASE src")
    con.execute("VACUUM")
    con.commit()

    got = {r[0] for r in con.execute("SELECT message_id FROM messages")} if "messages" in common else set()
    integ = con.execute("PRAGMA integrity_check").fetchone()[0]
    counts = {t: con.execute("SELECT COUNT(*) FROM %s" % t).fetchone()[0] for t in sorted(common)}
    con.close()

    missing = expected - got
    print("\n=== MERGED: %s  (%.1f MB) ===" % (os.path.basename(args.output),
                                               os.path.getsize(args.output) / 1e6))
    for t, n in counts.items():
        print("  %-15s %s" % (t, f"{n:,}"))
    print("  expected unique messages: %s" % f"{len(expected):,}")
    print("  missing after merge     : %d   (must be 0)" % len(missing))
    print("  integrity               : %s" % integ)
    ok = not missing and integ == "ok"
    print("RESULT:", "OK - no data lost, structure preserved" if ok else "!! CHECK FAILED - do not import")
    sys.exit(0 if ok else 2)


if __name__ == "__main__":
    main()
