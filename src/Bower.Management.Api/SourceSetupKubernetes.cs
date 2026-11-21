using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static Bower.Management.Api.SourceSetupRegistry;

namespace Bower.Management.Api;

/// <summary>
/// Bounded, allow-listed Kubernetes container log source (src/Bower.Source.Kubernetes,
/// docs/deployment/kubernetes-source.md, deploy/kubernetes/daemonset.yaml). Enforces
/// explicit namespaces and label selectors (no cluster-wide collection, no pod annotation discovery).
/// </summary>
internal sealed partial class KubernetesSourceSetup : SourceSetupType
{
    public override string Id => "kubernetes";

    public override string Title => "Kubernetes container logs";

    public override string Summary =>
        "Tails CRI container logs for explicitly allow-listed namespaces and pod label selectors using a namespaced DaemonSet.";

    public override string Why =>
        "Container clusters mix noisy application stdout with security events. Requiring explicit namespaces and label selectors avoids cluster-wide collection and uses namespaced read-only pod RBAC instead of ClusterRole.";

    public override IReadOnlyList<string> Needs =>
    [
        "A Kubernetes cluster using CRI-format container logs under /var/log/pods.",
        "Explicit allow-listed namespace names and exact pod label selectors (key=value).",
        "A namespaced Role and RoleBinding granting get/list on pods only (never ClusterRole)."
    ];

    public override IReadOnlyList<SourceFieldRule> Fields { get; } =
    [
        new(
            new SourceFieldDefinition(
                "namespaces", "Allowed namespaces", SourceFieldKinds.NameList, true,
                "Explicit Kubernetes namespaces (1 to 32, lowercase DNS-1123 labels). Wildcards and cluster-wide collection are refused.",
                "security-apps", Placeholder: "security-apps, payments", MaximumLength: 512),
            DnsLabelPattern(),
            "Each namespace must be lowercase letters, digits or hyphens (1 to 63 characters, starting and ending with a letter or digit)."),
        new(
            new SourceFieldDefinition(
                "labelSelectors", "Pod label selectors (key=value)", SourceFieldKinds.NameList, true,
                "Explicit key=value selectors (1 to 16). Pods must match at least one selector to be collected.",
                "bower.security/collect=true", Placeholder: "bower.security/collect=true", MaximumLength: 512),
            LabelSelectorPattern(),
            "Use exact key=value pairs (for example bower.security/collect=true) with no wildcards."),
        new(
            new SourceFieldDefinition(
                "allowedMetadataLabels", "Allowed pod metadata label keys", SourceFieldKinds.NameList, false,
                "Optional allow-list of pod label keys (up to 16) to attach as k8s.label.* attributes.",
                "app.kubernetes.io/name", Placeholder: "app.kubernetes.io/name, tier", MaximumLength: 512),
            LabelKeyPattern(),
            "Label keys may use letters, digits, '.', '_', '-' and '/' only."),
        new(new SourceFieldDefinition(
            "podLogRoot", "Node pod log directory", SourceFieldKinds.FilePath, true,
            "Read-only hostPath mounted from the node containing CRI container logs.",
            "/var/log/pods", Placeholder: "/var/log/pods", MaximumLength: 260)),
        new(new SourceFieldDefinition(
            "maxPods", "Maximum pods per node", SourceFieldKinds.Number, true,
            "Upper bound on pods watched per node (1 to 500).",
            "200", Minimum: 1, Maximum: 500, MaximumLength: 4)),
        new(new SourceFieldDefinition(
            "maxBatchLines", "Maximum lines per poll", SourceFieldKinds.Number, true,
            "Upper bound on CRI log lines read per poll cycle (1 to 500).",
            "256", Minimum: 1, Maximum: 500, MaximumLength: 4)),
        new(new SourceFieldDefinition(
            "startAtEnd", "Start new container logs at end", SourceFieldKinds.Boolean, true,
            "When true, newly discovered container logs start at the current end instead of replaying historical lines.",
            "true", MaximumLength: 5)),
        Application("k8s-security", "The application name events carry in Sentinel."),
        SourceSetupRegistry.Environment(),
        Silence()
    ];

    public override string CheckDescription =>
        "Bower watches the collector's heartbeat for the application and environment above. It turns green when the collector reports Kubernetes security events.";

    public override string Guide => "docs/deployment/kubernetes-source.md";

    public override void Validate(IReadOnlyDictionary<string, string> values, List<SetupCheck> checks)
    {
        IReadOnlyList<string> namespaces = List(values, "namespaces");
        IReadOnlyList<string> selectors = List(values, "labelSelectors");
        IReadOnlyList<string> allowedLabels = List(values, "allowedMetadataLabels");

        if (namespaces.Count is 0 or > 32)
        {
            checks.Add(Fail(
                "namespaces",
                "Kubernetes requires between 1 and 32 explicitly allow-listed namespaces.",
                "List 1 to 32 lowercase namespace names."));
        }

        if (selectors.Count is 0 or > 16)
        {
            checks.Add(Fail(
                "labelSelectors",
                "Kubernetes requires between 1 and 16 explicit key=value pod label selectors.",
                "List 1 to 16 selectors such as bower.security/collect=true."));
        }

        if (allowedLabels.Count > 16)
        {
            checks.Add(Fail(
                "allowedMetadataLabels",
                "Allowed pod metadata label keys cannot exceed 16.",
                "List at most 16 pod label keys."));
        }
    }

    public override SourceSetupBuild Build(IReadOnlyDictionary<string, string> values, string collectorId)
    {
        IReadOnlyList<string> namespaces = List(values, "namespaces");
        IReadOnlyList<string> selectors = List(values, "labelSelectors");
        IReadOnlyList<string> allowedLabels = List(values, "allowedMetadataLabels");

        JsonArray selectorArray = new();
        foreach (string entry in selectors)
        {
            int split = entry.IndexOf('=', StringComparison.Ordinal);
            selectorArray.Add((JsonNode)new JsonObject
            {
                ["key"] = entry[..split],
                ["value"] = entry[(split + 1)..]
            });
        }

        JsonObject config = new()
        {
            ["apiVersion"] = "bower.security/v1",
            ["kind"] = "KubernetesLogSource",
            ["podLogRoot"] = values["podLogRoot"],
            ["namespaces"] = new JsonArray([.. namespaces.Select(ns => JsonValue.Create(ns))]),
            ["labelSelectors"] = selectorArray,
            ["allowedMetadataLabels"] = new JsonArray([.. allowedLabels.Select(key => JsonValue.Create(key))]),
            ["maxLineBytes"] = 65_536,
            ["maxPartialBytes"] = 65_536,
            ["maxBatchLines"] = int.Parse(values["maxBatchLines"], CultureInfo.InvariantCulture),
            ["maxPods"] = int.Parse(values["maxPods"], CultureInfo.InvariantCulture),
            ["startAtEnd"] = string.Equals(values["startAtEnd"], "true", StringComparison.Ordinal),
            ["application"] = values["application"],
            ["environment"] = values["environment"]
        };

        SourceSetupFile kubernetesFile = new(
            "kubernetes.json",
            "/etc/bower/kubernetes.json",
            "Allow-listed Kubernetes container log source settings. Mounted read-only into the Bower DaemonSet.",
            Json(config));

        string primaryNs = namespaces[0];
        string rbacSnippet =
            $"# Namespaced read-only pod discovery (repeat per allowed namespace; never use ClusterRole)\n" +
            $"apiVersion: rbac.authorization.k8s.io/v1\n" +
            $"kind: Role\n" +
            $"metadata:\n" +
            $"  name: bower-pod-reader\n" +
            $"  namespace: {primaryNs}\n" +
            $"rules:\n" +
            $"  - apiGroups: [\"\"]\n" +
            $"    resources: [\"pods\"]\n" +
            $"    verbs: [\"get\", \"list\"]\n" +
            $"---\n" +
            $"# Deploy hardened DaemonSet from deploy/kubernetes/daemonset.yaml\n";

        return new SourceSetupBuild(
            [kubernetesFile, Expectations(values["application"], values["environment"], values["maximumSilenceMinutes"])],
            [
                new("kubernetes-daemonset", "BOWER_KUBERNETES_CONFIG", "/etc/bower/kubernetes.json"),
                ExpectationsVariable()
            ],
            [new SourceSetupSnippet(
                "Kubernetes: namespaced Role (pods get/list only)",
                "Apply in each allow-listed namespace alongside deploy/kubernetes/daemonset.yaml.",
                "yaml",
                rbacSnippet)],
            ApplicationVerification(values["application"], values["environment"]));
    }

    public override JsonObject Sample(IReadOnlyDictionary<string, string> values)
    {
        IReadOnlyList<string> namespaces = List(values, "namespaces");
        string primaryNs = namespaces.Count > 0 ? namespaces[0] : "security-apps";
        return new JsonObject
        {
            ["eventType"] = "auth_failure",
            ["eventAction"] = "container.auth.denied",
            ["eventResult"] = "failure",
            ["application"] = new JsonObject { ["name"] = values["application"], ["environment"] = values["environment"] },
            ["actor"] = new JsonObject { ["username"] = "service.user@example.org" },
            ["source"] = new JsonObject { ["ipAddress"] = "198.51.100.77" },
            ["attributes"] = new JsonObject
            {
                ["k8s.namespace"] = primaryNs,
                ["k8s.pod"] = "auth-api-7d9f8c6b4-x2k9p",
                ["k8s.container"] = "auth-api",
                ["k8s.stream"] = "stdout",
                ["auth.detail"] = "Rejected bearer token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.dummysignature123456"
            }
        };
    }

    [GeneratedRegex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")]
    private static partial Regex DnsLabelPattern();

    [GeneratedRegex("^[A-Za-z0-9._/-]{1,128}=[A-Za-z0-9._-]{1,63}$")]
    private static partial Regex LabelSelectorPattern();

    [GeneratedRegex("^[A-Za-z0-9._/-]{1,128}$")]
    private static partial Regex LabelKeyPattern();
}
