# Azure output instructions

Use supported Azure Monitor Logs Ingestion APIs and token credentials. Never
persist tokens or log credentials. Isolate poison records, honor retry signals,
bound request size and concurrency, and record acknowledgements. Upload success
is not proof of queryability.
