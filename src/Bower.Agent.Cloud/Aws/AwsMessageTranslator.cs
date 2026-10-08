using System.Net;
using System.Text;
using System.Text.Json;
using Amazon.S3;
using Amazon.S3.Model;
using Bower.Contracts;
using Bower.Source.Aws;

namespace Bower.Agent.Cloud.Aws;

/// <summary>Reads one S3 object, bounded, from the expected bucket owner.</summary>
public interface IS3ObjectReader
{
    Task<byte[]> ReadAsync(string bucket, string key, string expectedOwner, long maximumBytes, CancellationToken cancellationToken);
}

public sealed class S3ObjectReader(IAmazonS3 s3) : IS3ObjectReader
{
    public async Task<byte[]> ReadAsync(
        string bucket,
        string key,
        string expectedOwner,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        try
        {
            // ExpectedBucketOwner stops a notification from steering reads to another account's bucket.
            using GetObjectResponse response = await s3.GetObjectAsync(
                new GetObjectRequest { BucketName = bucket, Key = key, ExpectedBucketOwner = expectedOwner },
                cancellationToken);
            if (response.ContentLength > maximumBytes)
            {
                throw new MalformedCloudMessageException($"S3 object is {response.ContentLength} bytes; maximum is {maximumBytes}");
            }

            using MemoryStream buffer = new();
            await response.ResponseStream.CopyToAsync(buffer, cancellationToken);
            return buffer.ToArray();
        }
        catch (AmazonS3Exception exception) when (exception.StatusCode == HttpStatusCode.NotFound)
        {
            // Deleted or expired before it was read; retrying cannot help.
            throw new MalformedCloudMessageException("S3 object no longer exists", exception);
        }
    }
}

/// <summary>
/// Turns SQS bodies into candidate events: EventBridge security events are mapped here;
/// S3 notifications for Firehose CloudWatch Logs objects yield the Bower envelopes inside.
/// </summary>
public sealed partial class AwsMessageTranslator(
    AwsQueueMessageParser parser,
    IS3ObjectReader? objects,
    AwsQueueSettings settings,
    TimeProvider clock,
    ILogger<AwsMessageTranslator> logger) : ICloudMessageTranslator
{
    public async Task<CloudTranslation> TranslateAsync(CloudMessage message, CancellationToken cancellationToken)
    {
        AwsQueueMessage parsed;
        try
        {
            parsed = parser.Parse(Encoding.UTF8.GetString(message.Body), clock.GetUtcNow());
        }
        catch (Exception exception) when (IsMalformed(exception))
        {
            throw new MalformedCloudMessageException(exception.GetType().Name, exception);
        }

        switch (parsed.Kind)
        {
            case AwsQueueMessageKind.Events:
                return new CloudTranslation(
                    parsed.Events.Select(item => JsonSerializer.Serialize(item, BowerJson.Options)).ToList(),
                    0,
                    null);
            case AwsQueueMessageKind.ObjectReferences:
                return await ReadObjectsAsync(parsed.Objects, cancellationToken);
            default:
                return CloudTranslation.Unsupported(parsed.Description ?? "unsupported");
        }
    }

    private async Task<CloudTranslation> ReadObjectsAsync(
        IReadOnlyList<AwsS3ObjectReference> references,
        CancellationToken cancellationToken)
    {
        List<string> events = [];
        int skipped = 0;
        int denied = 0;
        foreach (AwsS3ObjectReference reference in references)
        {
            if (objects is null || !settings.AllowedBuckets.Contains(reference.Bucket))
            {
                // Default deny: only buckets the operator listed are ever read.
                LogBucketNotAllowed(logger, reference.Bucket);
                denied++;
                continue;
            }

            if (reference.Size > settings.MaximumObjectBytes)
            {
                throw new MalformedCloudMessageException(
                    $"S3 object is {reference.Size} bytes; maximum is {settings.MaximumObjectBytes}");
            }

            byte[] content = await objects.ReadAsync(
                reference.Bucket,
                reference.Key,
                settings.AccountId,
                settings.MaximumObjectBytes,
                cancellationToken);
            try
            {
                using MemoryStream stream = new(content, writable: false);
                FirehoseLogObject result = FirehoseLogObjectReader.Read(
                    stream,
                    new FirehoseLogObjectOptions { SourceId = $"aws-s3:{settings.AccountId}" });
                events.AddRange(result.Envelopes);
                skipped += result.Skipped;
            }
            catch (Exception exception) when (IsMalformed(exception))
            {
                throw new MalformedCloudMessageException(exception.GetType().Name, exception);
            }
        }

        return denied == references.Count
            ? CloudTranslation.Unsupported("bucket not allowed")
            : new CloudTranslation(events, skipped, null);
    }

    private static bool IsMalformed(Exception exception) =>
        exception is AwsTelemetryMalformedRecordException
            or AwsTelemetryPayloadTooLargeException
            or AwsTelemetryBatchTooLargeException
            or JsonException;

    [LoggerMessage(EventId = 4101, Level = LogLevel.Warning,
        Message = "S3 notification for bucket {Bucket} ignored; add it to BOWER_AWS_S3_BUCKETS to read it.")]
    private static partial void LogBucketNotAllowed(ILogger logger, string bucket);
}
