using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using Amazon;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using Bower.Abstractions;

namespace Bower.Output.S3;

/// <summary>
/// Writes queued, already-redacted events to Amazon S3 as NDJSON objects, one conditional
/// PUT per object (<c>If-None-Match: *</c>, SHA-256 checksum, server-side encryption).
/// Delivered means S3 accepted the PUT; it is not Sentinel delivery. Objects are uploaded
/// in order; the first destination failure holds this and every later object, so events
/// stay queued without hammering a failing bucket.
/// </summary>
public sealed class S3Output : IOutputAdapter, IDisposable
{
    private readonly S3OutputOptions options;
    private readonly IAmazonS3 client;
    private readonly bool ownsClient;

    /// <summary>Production client: the AWS default credential chain, never static keys.</summary>
    public S3Output(S3OutputOptions options)
        : this(options, CreateClient(options), ownsClient: true)
    {
    }

    internal S3Output(S3OutputOptions options, IAmazonS3 client, bool ownsClient = false)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(client);
        options.Validate();
        this.options = options;
        this.client = client;
        this.ownsClient = ownsClient;
    }

    public string Id => options.Id;

    public async Task<DeliveryResult> DeliverAsync(
        IReadOnlyList<QueuedEvent> events,
        CancellationToken cancellationToken = default)
    {
        if (events.Count == 0)
        {
            return new DeliveryResult([], [], null);
        }

        (IReadOnlyList<S3PlannedObject> objects, IReadOnlyList<DeliveryFailure> rejected) = S3ObjectLayout.Plan(
            events, options.Prefix, options.CollectorId, options.MaximumObjectBytes, options.MaximumObjectEvents, options.Gzip);
        List<DeliveryFailure> failures = [.. rejected];
        List<string> acknowledged = [];
        Dictionary<string, string> acknowledgements = new(StringComparer.Ordinal);
        int index = 0;
        try
        {
            for (; index < objects.Count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string? code = await PutAsync(objects[index], cancellationToken);
                if (code is not null)
                {
                    for (int held = index; held < objects.Count; held++)
                    {
                        failures.AddRange(objects[held].EventIds.Select(id => new DeliveryFailure(id, code, true, null)));
                    }

                    index = objects.Count;
                    break;
                }

                acknowledged.AddRange(objects[index].EventIds);
                foreach (string eventId in objects[index].EventIds)
                {
                    acknowledgements[eventId] = Acknowledgement(options.Bucket, objects[index].Key);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Objects written before the deadline stay acknowledged; only unfinished ones retry.
            for (; index < objects.Count; index++)
            {
                failures.AddRange(objects[index].EventIds.Select(id => new DeliveryFailure(id, CancelledCode, true, null)));
            }
        }

        // Every event's acknowledgement names its own object; the batch-level value is the
        // first object's, for readers of the batch result only.
        return new DeliveryResult(
            acknowledged,
            failures,
            acknowledged.Count == 0 ? null : acknowledgements[acknowledged[0]])
        {
            EventAcknowledgements = acknowledgements
        };
    }

    public void Dispose()
    {
        if (ownsClient)
        {
            client.Dispose();
        }
    }

    /// <summary>One conditional PUT; null on success, otherwise a bounded failure code.</summary>
    private async Task<string?> PutAsync(S3PlannedObject item, CancellationToken cancellationToken)
    {
        byte[] content = options.Gzip ? Compress(item.Body) : item.Body;
        using MemoryStream stream = new(content, writable: false);
        PutObjectRequest request = new()
        {
            BucketName = options.Bucket,
            Key = item.Key,
            InputStream = stream,
            AutoCloseStream = false,
            ContentType = "application/x-ndjson",
            ChecksumAlgorithm = ChecksumAlgorithm.SHA256,
            ChecksumSHA256 = Convert.ToBase64String(SHA256.HashData(content)),
            IfNoneMatch = "*",
            UseChunkEncoding = false
        };
        // Unset: no header, so the bucket's default encryption (possibly a KMS key) applies.
        if (options.ServerSideEncryption is not null)
        {
            request.ServerSideEncryptionMethod = options.ServerSideEncryption == S3OutputOptions.SseKms
                ? ServerSideEncryptionMethod.AWSKMS
                : ServerSideEncryptionMethod.AES256;
        }

        if (options.KmsKeyId is not null)
        {
            request.ServerSideEncryptionKeyManagementServiceKeyId = options.KmsKeyId;
        }

        if (options.ExpectedBucketOwner is not null)
        {
            request.ExpectedBucketOwner = options.ExpectedBucketOwner;
        }

        if (options.Gzip)
        {
            request.Headers.ContentEncoding = "gzip";
        }

        request.Metadata.Add("bower-events", item.EventIds.Count.ToString(CultureInfo.InvariantCulture));
        try
        {
            await client.PutObjectAsync(request, cancellationToken);
            return null;
        }
        catch (AmazonServiceException exception) when (exception.StatusCode != 0)
        {
            // Service messages can carry ARNs; only whether one names KMS is kept.
            return Classify((int)exception.StatusCode, exception.ErrorCode,
                exception.Message?.Contains("kms", StringComparison.OrdinalIgnoreCase) == true);
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            // Transport and credential exceptions may contain secrets: never keep their text.
            return IsCredentialFailure(exception) ? CredentialFailedCode : UnavailableCode;
        }
    }

    public const string ThrottledCode = "destination-s3-throttled";
    public const string AccessDeniedCode = "destination-s3-access-denied";
    public const string KmsDeniedCode = "destination-s3-kms-denied";
    public const string NoSuchBucketCode = "destination-s3-no-such-bucket";
    public const string WrongRegionCode = "destination-s3-wrong-region";
    public const string CredentialFailedCode = "destination-s3-credential-failed";
    public const string UnavailableCode = "destination-s3-unavailable";
    public const string CancelledCode = "destination-s3-cancelled";
    public const string HttpCodePrefix = "destination-s3-http-";

    /// <summary>
    /// Maps an S3 error response to a destination code (same table as the Rust port).
    /// Null means success: 412 answers <c>If-None-Match: *</c> when the key already exists,
    /// and the key binds the collector, the exact event ids and the uncompressed body
    /// (<see cref="S3ObjectLayout.ObjectHash"/>), so the stored object holds byte-identical
    /// content. Every code is retryable: access,
    /// bucket, KMS and region faults need an operator, and the events wait in the queue.
    /// </summary>
    public static string? Classify(int status, string? errorCode, bool messageNamesKms)
    {
        if (status == 412)
        {
            return null;
        }

        return errorCode switch
        {
            "SlowDown" or "Throttling" or "ThrottlingException" or "RequestLimitExceeded" or "TooManyRequestsException"
                or "RequestThrottled" or "RequestThrottledException" => ThrottledCode,
            _ when status is 429 or 503 => ThrottledCode,
            not null when errorCode.StartsWith("KMS.", StringComparison.Ordinal) => KmsDeniedCode,
            "AccessDenied" when messageNamesKms => KmsDeniedCode,
            "InvalidAccessKeyId" or "SignatureDoesNotMatch" or "ExpiredToken" or "InvalidToken"
                or "TokenRefreshRequired" or "MissingSecurityHeader" => CredentialFailedCode,
            "AccessDenied" or "AllAccessDisabled" or "AccountProblem" or "InvalidPayer" => AccessDeniedCode,
            _ when status == 403 => AccessDeniedCode,
            "NoSuchBucket" => NoSuchBucketCode,
            "PermanentRedirect" or "AuthorizationHeaderMalformed" or "IllegalLocationConstraintException" => WrongRegionCode,
            _ when status == 301 => WrongRegionCode,
            _ when status is >= 100 and <= 599 => HttpCodePrefix + status.ToString(CultureInfo.InvariantCulture),
            _ => UnavailableCode
        };
    }

    /// <summary>Persisted with each acknowledged event: the object that holds it.</summary>
    public static string Acknowledgement(string bucket, string key) => $"s3://{bucket}/{key}";

    /// <summary>
    /// The default chain found no credentials, or could not use them. Network faults that
    /// stop a credential fetch count as unavailable, like any other outage.
    /// </summary>
    private static bool IsCredentialFailure(Exception exception)
    {
        for (Exception? item = exception; item is not null; item = item.InnerException)
        {
            if (item is HttpRequestException or IOException or TimeoutException or WebException
                or System.Net.Sockets.SocketException or OperationCanceledException)
            {
                return false;
            }
        }

        return exception is AmazonClientException
            && exception.Message.Contains("credentials", StringComparison.OrdinalIgnoreCase);
    }

    private static byte[] Compress(byte[] body)
    {
        using MemoryStream output = new();
        using (GZipStream gzip = new(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            gzip.Write(body);
        }

        return output.ToArray();
    }

    private static AmazonS3Client CreateClient(S3OutputOptions options)
    {
        options.Validate();
        AmazonS3Config config = new()
        {
            RegionEndpoint = RegionEndpoint.GetBySystemName(options.Region),
            RetryMode = RequestRetryMode.Standard,
            // Three attempts in memory; anything longer waits in the durable queue.
            MaxErrorRetry = 2,
            Timeout = TimeSpan.FromSeconds(60)
        };
        return new AmazonS3Client(config);
    }
}
