using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Contracts;

namespace Bower.Source.Aws;

public sealed partial class AwsSecurityEventMapper
{
    private SecurityEventEnvelope MapIamPermissionChange(SecurityEventEnvelope envelope, JsonElement record, string action)
    {
        (string? kind, string? nameKey, string? permissionKey, string direction) = action switch
        {
            "AttachUserPolicy" => ("user", "userName", "policyArn", "grant"),
            "DetachUserPolicy" => ("user", "userName", "policyArn", "revoke"),
            "AttachRolePolicy" => ("role", "roleName", "policyArn", "grant"),
            "DetachRolePolicy" => ("role", "roleName", "policyArn", "revoke"),
            "AttachGroupPolicy" => ("group", "groupName", "policyArn", "grant"),
            "DetachGroupPolicy" => ("group", "groupName", "policyArn", "revoke"),
            "AddUserToGroup" => ("group", "groupName", "groupName", "grant"),
            "RemoveUserFromGroup" => ("group", "groupName", "groupName", "revoke"),
            "UpdateAssumeRolePolicy" => ("role", "roleName", (string?)null, "replace"),
            _ => ((string?)null, (string?)null, (string?)null, "unknown")
        };
        if (kind is null)
        {
            return envelope;
        }

        JsonArray entries = [];
        string? target = null;
        string mode = "unavailable";
        if (record.TryGetProperty("requestParameters", out JsonElement request) && request.ValueKind != JsonValueKind.Null)
        {
            target = PermissionIdentifier(request, nameKey!);
            if (permissionKey is not null)
            {
                string member = action is "AddUserToGroup" or "RemoveUserFromGroup"
                    ? PermissionIdentifier(request, "userName") : target;
                entries.Add((JsonNode)new JsonObject
                {
                    ["member"] = member,
                    ["memberType"] = action is "AddUserToGroup" or "RemoveUserFromGroup" ? "user" : kind,
                    ["permission"] = PermissionIdentifier(request, permissionKey),
                    ["direction"] = direction
                });
                mode = "delta";
            }
            else if (request.TryGetProperty("policyDocument", out JsonElement policy) && policy.ValueKind != JsonValueKind.Null)
            {
                ReadTrustPolicy(policy, entries);
                mode = "replacement";
            }
        }

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
            Target = target is null ? envelope.Target : new TargetContext { Type = $"aws-iam-{kind}", Name = Clip(target, 256) },
            Change = new ChangeContext { Field = "permission_direction", NewValue = mode == "unavailable" ? "unknown" : direction },
            Attributes = attributes
        };
    }

    private void ReadTrustPolicy(JsonElement policy, JsonArray entries)
    {
        // CloudTrail commonly emits an object; the IAM API also accepts a JSON string
        // (sometimes URL encoded). Never carry the document or condition values onward.
        if (policy.ValueKind == JsonValueKind.String)
        {
            string text = policy.GetString()!;
            if (text.Length > 131_072)
            {
                throw PermissionContextError();
            }

            try
            {
                using JsonDocument parsed = JsonDocument.Parse(text.TrimStart().StartsWith('{') ? text : Uri.UnescapeDataString(text),
                    new JsonDocumentOptions { MaxDepth = 32 });
                ReadTrustPolicy(parsed.RootElement, entries);
                return;
            }
            catch (JsonException)
            {
                throw PermissionContextError();
            }
        }

        if (policy.ValueKind != JsonValueKind.Object || !policy.TryGetProperty("Statement", out JsonElement statements))
        {
            throw PermissionContextError();
        }

        foreach (JsonElement statement in OneOrMany(statements))
        {
            string effect = PermissionIdentifier(statement, "Effect");
            if (effect is not ("Allow" or "Deny") || !statement.TryGetProperty("Principal", out JsonElement principals)
                || !statement.TryGetProperty("Action", out JsonElement actions)
                || statement.TryGetProperty("NotPrincipal", out _) || statement.TryGetProperty("NotAction", out _))
            {
                throw PermissionContextError();
            }

            if (principals.ValueKind == JsonValueKind.String && principals.GetString() == "*")
            {
                AddTrustEntries("*", "wildcard", actions, effect, statement.TryGetProperty("Condition", out _), entries);
            }
            else if (principals.ValueKind == JsonValueKind.Object)
            {
                foreach (JsonProperty principal in principals.EnumerateObject())
                {
                    if (principal.Name is not ("AWS" or "Service" or "Federated" or "CanonicalUser"))
                    {
                        throw PermissionContextError();
                    }

                    foreach (JsonElement member in OneOrMany(principal.Value))
                    {
                        AddTrustEntries(PermissionIdentifier(member), principal.Name, actions, effect,
                            statement.TryGetProperty("Condition", out _), entries);
                    }
                }
            }
            else
            {
                throw PermissionContextError();
            }
        }
    }

    private void AddTrustEntries(string member, string kind, JsonElement actions, string effect, bool conditional, JsonArray entries)
    {
        foreach (JsonElement action in OneOrMany(actions))
        {
            if (entries.Count >= 64)
            {
                throw PermissionContextError();
            }

            entries.Add((JsonNode)new JsonObject
            {
                ["member"] = member,
                ["memberType"] = kind,
                ["permission"] = PermissionIdentifier(action),
                ["direction"] = "present",
                ["effect"] = effect,
                ["conditionPresent"] = conditional
            });
        }
    }

    private IEnumerable<JsonElement> OneOrMany(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Array)
        {
            if (value.GetArrayLength() > 64)
            {
                throw PermissionContextError();
            }

            foreach (JsonElement item in value.EnumerateArray())
            {
                yield return item;
            }
        }
        else
        {
            yield return value;
        }
    }

    private string PermissionIdentifier(JsonElement value, string name)
    {
        if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty(name, out JsonElement property))
        {
            throw PermissionContextError();
        }

        return PermissionIdentifier(property);
    }

    private string PermissionIdentifier(JsonElement value)
    {
        string? text = value.ValueKind == JsonValueKind.String ? value.GetString() : null;
        return !string.IsNullOrWhiteSpace(text) && text.Length <= 2048 && !text.Any(char.IsControl)
            ? text : throw PermissionContextError();
    }

    private AwsTelemetryPermissionContextException PermissionContextError() => new(options.SourceId);
}

public sealed class AwsTelemetryPermissionContextException(string sourceId)
    : InvalidOperationException($"AWS source '{sourceId}' permission context is malformed or exceeds its bounds.");
