using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace Bower.Management.Api;

public sealed record PrivacyFormField(string Path, string Action, int? MaxLength);
public sealed record PrivacyForm(string Id, string Version, string Description, IReadOnlyList<PrivacyFormField> Fields);
public sealed record PrivacyFormRequest(string Content, PrivacyForm? Form);
public sealed record PrivacyFormResult(PrivacyForm Form, string Content, PrivacyProfileValidation Validation, PrivacyProfilePreview Preview);

/// <summary>Edits a validated YAML tree, preserving advanced settings outside the form.</summary>
internal static class PrivacyProfileForm
{
    private const string Example = """
        {"eventType":"authentication_failure","actor":{"username":"alex.example@example.com"},"source":{"ipAddress":"192.0.2.10"},"attributes":{"message":"Synthetic security event for the guided privacy example","password":"synthetic-password"}}
        """;

    public static void Map(RouteGroupBuilder api)
    {
        api.MapPost("/privacy-profiles/form", async (
            PrivacyFormRequest request, ManagementStore store, CancellationToken cancellationToken) =>
        {
            try
            {
                // Strict collector validation comes before reading the representation tree.
                _ = PrivacyProfileInspector.Load(request.Content);
                YamlStream stream = new();
                stream.Load(new StringReader(request.Content));
                YamlMappingNode root = (YamlMappingNode)stream.Documents[0].RootNode;
                YamlMappingNode metadata = (YamlMappingNode)root.Children[new YamlScalarNode("metadata")];
                if (request.Form is { } form)
                {
                    if (form.Id is not { Length: > 0 and <= 128 }
                        || form.Version is not { Length: > 0 and <= 64 }
                        || form.Description is not { Length: <= 2000 }
                        || form.Fields is null || form.Fields.Count > 128
                        || form.Fields.Any(field => field is null || field.Path is not { Length: > 0 and <= 256 }
                            || field.Action is not ("replace" or "mask" or "hmac" or "truncate" or "remove" or "allow" or "alertonly" or "sha256" or "encrypt")))
                    {
                        return Results.BadRequest(new ErrorResponse("Use a profile name, a version and at most 128 supported field rules."));
                    }

                    metadata.Children[new YamlScalarNode("id")] = Text(form.Id);
                    metadata.Children[new YamlScalarNode("version")] = Text(form.Version);
                    metadata.Children[new YamlScalarNode("description")] = Text(form.Description);
                    YamlSequenceNode fields = new();
                    foreach (PrivacyFormField field in form.Fields)
                    {
                        YamlMappingNode entry = new() { { "path", Text(field.Path) }, { "action", Text(field.Action) } };
                        if (field.MaxLength is { } length)
                        {
                            entry.Add("maxLength", new YamlScalarNode(length.ToString(CultureInfo.InvariantCulture)));
                        }
                        fields.Add(entry);
                    }
                    root.Children[new YamlScalarNode("fields")] = fields;
                }

                string content = request.Content;
                if (request.Form is not null)
                {
                    using StringWriter writer = new(CultureInfo.InvariantCulture);
                    stream.Save(writer, assignAnchors: false);
                    content = writer.ToString();
                }
                PrivacyProfileValidation validation = PrivacyProfileInspector.Validate(content);
                if (!validation.Valid)
                {
                    return Results.BadRequest(new ErrorResponse("These settings do not form a valid privacy profile. Check the version, field paths and truncation lengths."));
                }
                string? latest = await store.LatestPrivacyProfileVersionAsync(validation.ProfileId!, cancellationToken);
                string? versionError = PrivacyProfileInspector.RequireGreater(validation.Version!, latest);
                if (versionError is not null)
                {
                    validation = validation with { Valid = false, Errors = [versionError] };
                }
                // Only this server-owned synthetic event can be previewed here.
                PrivacyProfilePreview preview = PrivacyProfileInspector.Preview(content, Example);
                if (preview.Redacted is { } redacted)
                {
                    Bower.Redaction.Privacy.PrivacyScanResult protectedPreview = new Bower.Redaction.Privacy.PrivacyEngine().RedactJson(redacted);
                    preview = protectedPreview.Succeeded
                        ? preview with { Redacted = protectedPreview.RedactedJson }
                        : preview with { Valid = false, Redacted = null, Errors = ["The example could not be protected."] };
                }
                return Results.Ok(new PrivacyFormResult(Read(root, metadata), content, validation, preview));
            }
            catch (Exception exception) when (exception is PrivacyProfileValidationException or YamlException or InvalidCastException)
            {
                return Results.BadRequest(new ErrorResponse("This profile cannot be opened with forms. Correct its YAML first."));
            }
        }).WithMetadata(new RequestSizeLimitAttribute(640 * 1024)).RequireAuthorization("Operate");
    }

    private static PrivacyForm Read(YamlMappingNode root, YamlMappingNode metadata)
    {
        List<PrivacyFormField> fields = [];
        if (root.Children.TryGetValue(new YamlScalarNode("fields"), out YamlNode? node) && node is YamlSequenceNode sequence)
        {
            foreach (YamlMappingNode field in sequence.Children.Cast<YamlMappingNode>())
            {
                string? length = Value(field, "maxLength");
                fields.Add(new PrivacyFormField(Value(field, "path")!,
                    Value(field, "action")!.Replace("-", string.Empty, StringComparison.Ordinal).ToLowerInvariant(),
                    length is null ? null : int.Parse(length, CultureInfo.InvariantCulture)));
            }
        }
        return new PrivacyForm(Value(metadata, "id")!, Value(metadata, "version")!, Value(metadata, "description") ?? "", fields);
    }

    private static string? Value(YamlMappingNode node, string key) =>
        node.Children.TryGetValue(new YamlScalarNode(key), out YamlNode? value) ? ((YamlScalarNode)value).Value : null;

    private static YamlScalarNode Text(string value) => new(value) { Style = ScalarStyle.DoubleQuoted };
}
