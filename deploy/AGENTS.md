# Deployment instructions

Plan-only by default. Azure mutations require explicit apply intent. Use Bicep
first, least-privilege identities, tenant-controlled resources and stable plan
hashes. Templates and rules remain disabled until client validation.

`deploy/aws` (CloudFormation) and `deploy/gcp` (Terraform) follow the same rule:
validate (`cfn-lint`, `ValidateTemplate`, `terraform validate`) freely, but create
or change AWS or Google Cloud resources only with explicit apply intent. Rules and
notification paths start disabled or scoped; keep queues encrypted, TLS-only and in
Australian regions by default, and grant agents consume-only access.
