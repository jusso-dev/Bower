data "google_project" "this" {
  project_id = var.project_id
}

locals {
  pubsub_agent = "serviceAccount:service-${data.google_project.this.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
  org_scope    = var.organization_id != ""
  wif          = var.aws_account_id != "" && var.aws_role_name != ""

  # Admin Activity entries for high-value methods, plus any denied admin call.
  audit_filter = join(" ", [
    "logName:\"cloudaudit.googleapis.com%2Factivity\" AND (",
    join(" OR ", [for m in var.audit_methods : "protoPayload.methodName:\"${m}\""]),
    "OR protoPayload.status.code=7)",
  ])
}

resource "google_pubsub_topic" "events" {
  name                       = var.name
  message_retention_duration = "86400s"

  message_storage_policy {
    allowed_persistence_regions = var.allowed_persistence_regions
    enforce_in_transit          = true
  }
}

resource "google_pubsub_topic" "dead_letter" {
  name = "${var.name}-dead-letter"

  message_storage_policy {
    allowed_persistence_regions = var.allowed_persistence_regions
    enforce_in_transit          = true
  }
}

# Holds dead-lettered messages for inspection and replay.
resource "google_pubsub_subscription" "dead_letter" {
  name                       = "${var.name}-dead-letter"
  topic                      = google_pubsub_topic.dead_letter.id
  message_retention_duration = "604800s"

  expiration_policy {
    ttl = ""
  }
}

resource "google_pubsub_subscription" "agent" {
  name                       = var.name
  topic                      = google_pubsub_topic.events.id
  ack_deadline_seconds       = 60
  message_retention_duration = "604800s"

  expiration_policy {
    ttl = ""
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.dead_letter.id
    max_delivery_attempts = var.max_delivery_attempts
  }
}

# The Pub/Sub service agent moves undeliverable messages to the dead-letter topic.
resource "google_pubsub_topic_iam_member" "dead_letter_publisher" {
  topic  = google_pubsub_topic.dead_letter.id
  role   = "roles/pubsub.publisher"
  member = local.pubsub_agent
}

resource "google_pubsub_subscription_iam_member" "dead_letter_subscriber" {
  subscription = google_pubsub_subscription.agent.id
  role         = "roles/pubsub.subscriber"
  member       = local.pubsub_agent
}

resource "google_logging_organization_sink" "audit" {
  count            = local.org_scope ? 1 : 0
  name             = var.name
  org_id           = var.organization_id
  include_children = true
  destination      = "pubsub.googleapis.com/${google_pubsub_topic.events.id}"
  filter           = local.audit_filter
}

resource "google_logging_project_sink" "audit" {
  count                  = local.org_scope ? 0 : 1
  name                   = var.name
  destination            = "pubsub.googleapis.com/${google_pubsub_topic.events.id}"
  filter                 = local.audit_filter
  unique_writer_identity = true
}

resource "google_pubsub_topic_iam_member" "sink_publisher" {
  topic  = google_pubsub_topic.events.id
  role   = "roles/pubsub.publisher"
  member = local.org_scope ? google_logging_organization_sink.audit[0].writer_identity : google_logging_project_sink.audit[0].writer_identity
}

resource "google_scc_notification_config" "findings" {
  count        = local.org_scope ? 1 : 0
  config_id    = var.name
  organization = var.organization_id
  description  = "Bower: active, unmuted HIGH and CRITICAL findings"
  pubsub_topic = google_pubsub_topic.events.id

  streaming_config {
    filter = var.scc_filter
  }
}

resource "google_pubsub_topic_iam_member" "scc_publisher" {
  count  = local.org_scope ? 1 : 0
  topic  = google_pubsub_topic.events.id
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:${google_scc_notification_config.findings[0].service_account}"
}

resource "google_pubsub_subscription_iam_member" "agent" {
  count        = var.subscriber_member != "" ? 1 : 0
  subscription = google_pubsub_subscription.agent.id
  role         = "roles/pubsub.subscriber"
  member       = var.subscriber_member
}

# Optional: let an agent running in AWS read the subscription with its IAM role,
# through Workload Identity Federation. No Google key is created.
resource "google_iam_workload_identity_pool" "aws" {
  count                     = local.wif ? 1 : 0
  workload_identity_pool_id = "${var.name}-aws"
  display_name              = "Bower agent in AWS"
}

resource "google_iam_workload_identity_pool_provider" "aws" {
  count                              = local.wif ? 1 : 0
  workload_identity_pool_id          = google_iam_workload_identity_pool.aws[0].workload_identity_pool_id
  workload_identity_pool_provider_id = "aws-${var.aws_account_id}"
  attribute_mapping = {
    "google.subject"     = "assertion.arn"
    "attribute.aws_role" = "assertion.arn.extract('assumed-role/{role}/')"
  }
  attribute_condition = "attribute.aws_role == \"${var.aws_role_name}\""

  aws {
    account_id = var.aws_account_id
  }
}

resource "google_pubsub_subscription_iam_member" "aws_agent" {
  count        = local.wif ? 1 : 0
  subscription = google_pubsub_subscription.agent.id
  role         = "roles/pubsub.subscriber"
  member       = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.aws[0].name}/attribute.aws_role/${var.aws_role_name}"
}
