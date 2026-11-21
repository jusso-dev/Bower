# Bower.Source.Kubernetes instructions

Bounded, allow-listed Kubernetes container log source (`/var/log/pods` + namespaced pod metadata).

- Default deny: configuration must specify explicit allow-listed `Namespaces` and
  `LabelSelectors`. No cluster-wide default collection and no pod annotation
  auto-discovery.
- Kubernetes RBAC is strictly namespaced `get`/`list` on `pods` in allow-listed
  namespaces only — never `ClusterRole` or secret/exec access.
- Reuse `Bower.Source.File.FileTailReader` for symlink-safe, rotation-aware,
  bounded file tailing and durable `FileTailCursor` persistence.
- Persist checkpoints strictly after caller acknowledgement (at-least-once).
- Parse CRI log lines (`<timestamp> <stream> <P|F> <message>`), bounding partial
  joins and rejecting malformed/oversized lines safely.
- Forward only validated Bower envelopes; unrecognised unstructured stdout lines
  are dropped here (Bower is not a generic log shipper).
- Attach minimal pod metadata (`k8s.namespace`, `k8s.pod`, `k8s.container`) and
  only explicitly allow-listed pod labels; all labels pass through the privacy engine.
- Never log raw log lines, ServiceAccount tokens, or raw API responses.
