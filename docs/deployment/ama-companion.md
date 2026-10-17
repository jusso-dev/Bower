# AMA companion mode

Set `BOWER_OUTPUT=ama-spool` and `BOWER_AMA_SPOOL_PATH` to a restrictive local
directory. Bower writes `active/*.tmp`, flushes each file, then atomically renames
it to `ready/*.jsonl` and syncs the ready directory (Linux and macOS), so a ready
file survives a power loss before its events are acknowledged. Configure AMA/DCR
collection against ready files only.

Files are named `{collector}-{stream}-{20-digit sequence}.jsonl`. On start Bower
continues the sequence after the highest one already in `ready/` or `active/`, so
a restart never collides with a file AMA has not consumed yet, and deletes its own
leftover `active/*.tmp` files (their events were never acknowledged and are
redelivered from the queue). A failed write or rename removes its temporary file;
the retry uses the next sequence number.

Each line is one complete UTF-8 JSON object. Bower never modifies AMA binaries or
unsupported internals. Monitor ready-file age, count and disk quota. Delete files
only after AMA's supported collection lifecycle; Bower's local queue
acknowledgement means spool creation, not Log Analytics query proof.
