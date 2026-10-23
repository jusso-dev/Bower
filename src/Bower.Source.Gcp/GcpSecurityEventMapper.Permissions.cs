using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Contracts;

namespace Bower.Source.Gcp;

public sealed partial class GcpSecurityEventMapper
{
    private SecurityEventEnvelope MapIamPermissionChange(SecurityEventEnvelope envelope, JsonElement payload, string? resourceName)
    {
        JsonArray entries = [];
        string mode = "unavailable";
        string direction = "unknown";
        // serviceData is the established AuditData shape; newer services use metadata.
        // Prefer the authoritative delta, never infer removals from a replacement policy.
        if (TryPermissionPath(payload, out JsonElement deltas, "serviceData", "policyDelta", "bindingDeltas")
            || TryPermissionPath(payload, out deltas, "metadata", "policyDelta", "bindingDeltas"))
        {
            RequirePermissionArray(deltas);
            mode = "delta";
            foreach (JsonElement delta in deltas.EnumerateArray())
            {
                string entryDirection = PermissionIdentifier(delta, "action") switch
                {
                    "ADD" => "grant",
                    "REMOVE" => "revoke",
                    _ => throw PermissionContextError()
                };
                AddPermissionEntry(entries, PermissionIdentifier(delta, "member"), PermissionIdentifier(delta, "role"),
                    entryDirection, delta.TryGetProperty("condition", out _));
                direction = direction == "unknown" ? entryDirection : direction == entryDirection ? direction : "mixed";
            }
        }
        else if (TryPermissionPath(payload, out JsonElement bindings, "request", "policy", "bindings"))
        {
            RequirePermissionArray(bindings);
            mode = "replacement";
            direction = "replace";
            foreach (JsonElement binding in bindings.EnumerateArray())
            {
                string role = PermissionIdentifier(binding, "role");
                if (!binding.TryGetProperty("members", out JsonElement members))
                {
                    throw PermissionContextError();
                }

                RequirePermissionArray(members);
                foreach (JsonElement member in members.EnumerateArray())
                {
                    AddPermissionEntry(entries, PermissionIdentifier(member), role, "present", binding.TryGetProperty("condition", out _));
                }
            }
        }

        string? target = resourceName is null ? null : PermissionIdentifier(resourceName);
        JsonObject context = new()
        {
            ["mode"] = mode,
            ["target"] = target,
            ["targetNameTruncated"] = target?.Length > 256,
            ["entries"] = entries
        };
        string json = context.ToJsonString();
        if (Encoding.UTF8.GetByteCount(json) > 32_768)
        {
            throw PermissionContextError();
        }

        using JsonDocument document = JsonDocument.Parse(json);
        Dictionary<string, JsonElement> attributes = envelope.Attributes is null ? new(StringComparer.Ordinal) : new(envelope.Attributes);
        attributes["cloud.permissionChanges"] = document.RootElement.Clone();
        return envelope with
        {
            Target = envelope.Target! with { Name = Clip(target, 256) },
            Change = new ChangeContext { Field = "permission_direction", NewValue = direction },
            Attributes = attributes
        };
    }

    private void AddPermissionEntry(JsonArray entries, string member, string role, string direction, bool conditional)
    {
        if (entries.Count >= 64)
        {
            throw PermissionContextError();
        }

        entries.Add((JsonNode)new JsonObject
        {
            ["member"] = member,
            ["permission"] = role,
            ["direction"] = direction,
            ["conditionPresent"] = conditional
        });
    }

    private void RequirePermissionArray(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > 64)
        {
            throw PermissionContextError();
        }
    }

    private bool TryPermissionPath(JsonElement value, out JsonElement result, params string[] path)
    {
        foreach (string name in path)
        {
            if (value.ValueKind != JsonValueKind.Object)
            {
                throw PermissionContextError();
            }

            if (!value.TryGetProperty(name, out value))
            {
                result = default;
                return false;
            }
        }

        result = value;
        return true;
    }

    private string PermissionIdentifier(JsonElement value, string name)
    {
        if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty(name, out JsonElement property))
        {
            throw PermissionContextError();
        }

        return PermissionIdentifier(property);
    }

    private string PermissionIdentifier(JsonElement value) =>
        PermissionIdentifier(value.ValueKind == JsonValueKind.String ? value.GetString() : null);

    private string PermissionIdentifier(string? text) =>
        !string.IsNullOrWhiteSpace(text) && text.Length <= 2048 && !text.Any(char.IsControl)
            ? text : throw PermissionContextError();

    private GcpTelemetryMalformedException PermissionContextError() =>
        new(options.SourceId, "permission context is malformed or exceeds its bounds");
}
