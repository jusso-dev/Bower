using System.Globalization;
using System.Text;
using Amazon.SQS;
using Amazon.SQS.Model;

namespace Bower.Agent.Cloud.Aws;

/// <summary>
/// SQS long-poll consumer. Messages are deleted only after acknowledgement; failed or
/// malformed messages return to the queue and reach its redrive dead-letter queue.
/// </summary>
public sealed class SqsMessageSource(IAmazonSQS sqs, Uri queueUrl) : ICloudMessageSource
{
    private const int MaximumVisibilitySeconds = 43_200;

    public string Name => "aws-sqs";

    public async Task<IReadOnlyList<CloudMessage>> ReceiveAsync(int maximum, CancellationToken cancellationToken)
    {
        ReceiveMessageResponse response = await sqs.ReceiveMessageAsync(
            new ReceiveMessageRequest
            {
                QueueUrl = queueUrl.ToString(),
                MaxNumberOfMessages = Math.Clamp(maximum, 1, 10),
                WaitTimeSeconds = 20,
                MessageSystemAttributeNames = ["ApproximateReceiveCount"]
            },
            cancellationToken);

        return (response.Messages ?? [])
            .Select(message => new CloudMessage(
                message.MessageId,
                message.ReceiptHandle,
                Encoding.UTF8.GetBytes(message.Body ?? string.Empty),
                message.Attributes is not null
                && message.Attributes.TryGetValue("ApproximateReceiveCount", out string? count)
                && int.TryParse(count, NumberStyles.Integer, CultureInfo.InvariantCulture, out int attempts)
                    ? attempts
                    : 0))
            .ToList();
    }

    public Task AcknowledgeAsync(CloudMessage message, CancellationToken cancellationToken) =>
        sqs.DeleteMessageAsync(
            new DeleteMessageRequest { QueueUrl = queueUrl.ToString(), ReceiptHandle = message.Handle },
            cancellationToken);

    public Task ReleaseAsync(CloudMessage message, TimeSpan delay, CancellationToken cancellationToken) =>
        SetVisibilityAsync(message, delay, cancellationToken);

    public Task ExtendAsync(CloudMessage message, TimeSpan lease, CancellationToken cancellationToken) =>
        SetVisibilityAsync(message, lease, cancellationToken);

    private async Task SetVisibilityAsync(CloudMessage message, TimeSpan duration, CancellationToken cancellationToken) =>
        await sqs.ChangeMessageVisibilityAsync(
            new ChangeMessageVisibilityRequest
            {
                QueueUrl = queueUrl.ToString(),
                ReceiptHandle = message.Handle,
                VisibilityTimeout = (int)Math.Clamp(duration.TotalSeconds, 0, MaximumVisibilitySeconds)
            },
            cancellationToken);
}
