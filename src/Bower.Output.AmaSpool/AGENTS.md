# AMA spool output instructions

Write UTF-8 JSON Lines through restrictive temporary files, flush, then atomically
rename into ready directory. Never split records. Enforce size/backlog bounds and
emit health failures. Bower is an AMA companion, not an AMA plugin.
