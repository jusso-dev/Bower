# AMA companion mode

Set `BOWER_OUTPUT=ama-spool` and `BOWER_AMA_SPOOL_PATH` to a restrictive local
directory. Bower writes `active/*.tmp`, flushes each file, then atomically renames
it to `ready/*.jsonl`. Configure AMA/DCR collection against ready files only.

Each line is one complete UTF-8 JSON object. Bower never modifies AMA binaries or
unsupported internals. Monitor ready-file age, count and disk quota. Delete files
only after AMA's supported collection lifecycle; Bower's local queue
acknowledgement means spool creation, not Log Analytics query proof.
