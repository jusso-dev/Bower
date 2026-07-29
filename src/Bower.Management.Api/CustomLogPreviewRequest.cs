using Bower.Pipeline;

namespace Bower.Management.Api;

public sealed record CustomLogPreviewRequest(
    CustomLogInput Input,
    CustomLogParserConfiguration Configuration);
