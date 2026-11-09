# Azure output instructions

Use supported Azure Monitor Logs Ingestion APIs and token credentials. Never
persist tokens or log credentials. Isolate poison records, honor retry signals,
bound request size and concurrency, and record acknowledgements. Upload success
is not proof of queryability.

Request concurrency is adaptive (`AdaptiveConcurrencyController`): keep the controller
deterministic, bounded by `MaximumConcurrency`, and its trace test passing.
Pauses and back-pressure never hold events outside the durable queue.
