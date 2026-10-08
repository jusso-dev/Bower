variable "project_id" {
  description = "Project that holds the Bower topic and subscription."
  type        = string
}

variable "organization_id" {
  description = "Organisation id (digits). When set, the audit sink covers the whole organisation and SCC notifications are created. Leave empty for a single-project sink without SCC."
  type        = string
  default     = ""
}

variable "region" {
  description = "Default region for regional resources."
  type        = string
  default     = "australia-southeast1"
}

variable "allowed_persistence_regions" {
  description = "Pub/Sub message storage policy. Messages are only stored in these regions."
  type        = list(string)
  default     = ["australia-southeast1", "australia-southeast2"]

  validation {
    condition     = alltrue([for r in var.allowed_persistence_regions : startswith(r, "australia-")])
    error_message = "Keep Bower messages in Australian regions (australia-southeast1 or australia-southeast2)."
  }
}

variable "name" {
  description = "Name prefix for the topic, subscription and sink."
  type        = string
  default     = "bower-security"
}

variable "subscriber_member" {
  description = "IAM member that runs the Bower cloud agent, for example serviceAccount:bower-agent@PROJECT.iam.gserviceaccount.com (GKE Workload Identity or Cloud Run) or a principal:// / principalSet:// Workload Identity Federation member. Leave empty to grant later."
  type        = string
  default     = ""
}

variable "aws_account_id" {
  description = "Optional. Creates a Workload Identity Federation pool so an agent running in this AWS account (with aws_role_name) can read the subscription without a Google key."
  type        = string
  default     = ""
}

variable "aws_role_name" {
  description = "IAM role name of the agent in aws_account_id (instance profile, ECS task or IRSA role)."
  type        = string
  default     = ""
}

variable "max_delivery_attempts" {
  description = "Deliveries before a message moves to the dead-letter topic. The agent stops pulling while the collector is down."
  type        = number
  default     = 10
}

variable "scc_filter" {
  description = "Security Command Center findings to forward."
  type        = string
  default     = "state = \"ACTIVE\" AND mute != \"MUTED\" AND (severity = \"HIGH\" OR severity = \"CRITICAL\")"
}

variable "audit_methods" {
  description = "Admin Activity method name fragments to forward (matched with the Logging ':' operator). Permission-denied admin calls are always forwarded."
  type        = list(string)
  default = [
    "SetIamPolicy",
    "CreateServiceAccountKey",
    "UploadServiceAccountKey",
    "CreateServiceAccount",
    "DisableServiceAccountKey",
    "CreateRole",
    "UpdateRole",
    "CreateSink",
    "UpdateSink",
    "DeleteSink",
    "CreateExclusion",
    "UpdateExclusion",
    "DeleteBucket",
    "UpdateBucket",
    "SetOrgPolicy",
    "DeleteNotificationConfig",
    "UpdateNotificationConfig",
    "compute.firewalls.insert",
    "compute.firewalls.patch",
    "DestroyCryptoKeyVersion",
    "UpdateCryptoKeyPrimaryVersion",
    "CreateWorkloadIdentityPoolProvider",
    "UpdateWorkloadIdentityPoolProvider",
  ]
}
