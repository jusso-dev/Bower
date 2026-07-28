# AWS EC2 agent instructions

Host collectors stay read-only and path-bounded. Metadata enrichment uses IMDSv2
when available but unit tests must inject metadata. Never log raw host payloads
or credentials.
