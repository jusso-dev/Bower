# Kubernetes container log source

`Bower.Source.Kubernetes` collects allow-listed security telemetry from container logs
under `/var/log/pods` on Linux nodes with minimal pod metadata enrichment.

## Selection and least privilege

- **No cluster-wide default collection:** `KubernetesLogSourceOptions` requires explicit
  allow-listed `Namespaces` (DNS-1123 names, max 32) and explicit `LabelSelectors`
  (`key=value`, max 16).
- **No pod annotation auto-discovery:** pods cannot opt themselves into collection via
  annotations. Only operator-approved namespaces and label selectors are queried.
- **Namespaced RBAC only:** grant the DaemonSet `ServiceAccount` a namespaced `Role`
  (`get`, `list` on `pods`) strictly in each approved namespace — see
  [`deploy/kubernetes/daemonset.yaml`](../../deploy/kubernetes/daemonset.yaml). Never
  use a `ClusterRole` or secret/exec permissions.
- **Minimal metadata:** attaches `k8s.namespace`, `k8s.pod`, `k8s.container`,
  `k8s.stream`, and only pod label keys explicitly named in `AllowedMetadataLabels`. All
  labels pass through Bower's Privacy & Secret Protection Engine before persistence.

## CRI parsing, rotation and checkpoints

- Reuses `Bower.Source.File.FileTailReader` for symlink-safe, bounded file reads with
  rename and copytruncate rotation detection.
- Parses standard CRI container log lines (`<RFC3339 timestamp> <stdout|stderr> <P|F> <message>`),
  joining partial (`P`) fragments up to `MaxPartialBytes` (default 64 KiB) until the final
  (`F`) line arrives. Malformed and oversized lines are counted and skipped safely.
- Only validated Bower `SecurityEventEnvelope` JSON records are forwarded; unrecognised
  unstructured stdout noise is dropped at the source.
- Checkpoints (`FileTailCursor`) are persisted in `ISourceCursorStore` under
  `k8s:<namespace>/<podUid>/<container>` strictly **after** caller acknowledgement,
  surviving restarts and log rotation without loss or duplicates. Deterministic `EventId`
  values derived from `(podUid, container, fileFingerprint, startOffset)` deduplicate
  replays.
