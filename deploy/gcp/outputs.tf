output "subscription" {
  description = "Set as BOWER_GCP_SUBSCRIPTION for the Bower cloud agent."
  value       = google_pubsub_subscription.agent.id
}

output "dead_letter_subscription" {
  description = "Inspect dead-lettered messages here; republish to the topic after fixing the cause."
  value       = google_pubsub_subscription.dead_letter.id
}

output "audit_filter" {
  value = local.audit_filter
}

output "aws_credential_config_command" {
  description = "Run once to create the external_account file for an agent in AWS (it holds no secret)."
  value = local.wif ? join(" ", [
    "gcloud iam workload-identity-pools create-cred-config",
    google_iam_workload_identity_pool_provider.aws[0].name,
    "--aws --enable-imdsv2 --output-file=bower-gcp-wif.json",
  ]) : null
}
