# Choose a deployment

Choose where Bower runs before connecting a source. Start with the supported guide
for your environment, then return to [your first verified event](first-event.md).

| Environment | Start here | What to check |
| --- | --- | --- |
| Linux hosts | [deb/rpm packages and Ansible](../deployment/installers.md) | Service identity, queue storage and outbound connectivity. |
| Windows hosts | [MSI installer](../deployment/installers.md) and [Windows Event Log](../deployment/windows-event-log-source.md) | The current source has a narrow channel/event allow-list. WEC-first rollout remains planned. |
| Containers | [Container images](../deployment/container-images.md), [console](../deployment/console-image.md), [Docker sidecar](../deployment/docker-sidecar.md) | Durable volumes and explicit source opt-in. |
| AWS servers with the CloudWatch agent | [Quick start: CloudWatch agent](aws-cloudwatch-agent.md) | Events reach CloudWatch Logs before Bower redacts them; keep retention short. |
| Linux Azure VMs or Arc servers with Azure Monitor Agent | [Quick start: Azure Monitor Agent](azure-monitor-agent.md) | Any local account can write rows on this path; compare the [three Azure paths](../deployment/ama-syslog-output.md#which-azure-path). Rate limits and a free syslog facility. |
| AWS | [AWS security sources](../deployment/aws.md) | Queue permissions and least privilege. |
| Google Cloud | [GCP security sources](../deployment/gcp.md) | Pub/Sub acknowledgement and forwarding configuration. |
| Azure Functions | [Azure Functions collector](../deployment/azure-function.md) | This path currently has no durable queue; durable ingest is tracked in issue #137. |
| Segmented networks | [Relay mode](../deployment/relay.md) | Mutual TLS, allowed collectors and downstream connectivity. |

## Planned deployment paths

Kubernetes container sources, full WEC/GPO rollout and signed air-gapped bundle
workflows are still being developed. An offline installer does not mean the entire
product supports disconnected operation. Track [open work on GitHub](https://github.com/jusso-dev/Bower/issues)
and use the current deployment guides as the source of truth.

Infrastructure templates are plan-first. Review the plan, identities and cost
before applying it. [Cloud permission context](../deployment/cloud-permission-context.md)
explains what each credential is allowed to do.
