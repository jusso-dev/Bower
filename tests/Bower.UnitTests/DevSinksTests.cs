using System.IO.Compression;
using System.Text;
using Bower.DevSinks;
using Bower.Output.AmaSyslog;

namespace Bower.UnitTests;

/// <summary>The Aspire harness stand-ins read exactly what Bower outputs write.</summary>
public sealed class DevSinksTests
{
    [Fact]
    public void SyslogFrameUsesTheAmaSyslogPrefix() =>
        Assert.Equal(AmaSyslogOutput.MessagePrefix, SyslogFrame.MessagePrefix);

    [Fact]
    public void SyslogFrameDecodesTheEnvelope()
    {
        const string envelope = """{"eventId":"e-1","eventType":"authentication_failure"}""";
        byte[] datagram = Encoding.ASCII.GetBytes(
            "<165>Nov 18 13:39:07 bower: bower-b64:" + Convert.ToBase64String(Encoding.UTF8.GetBytes(envelope)));

        Assert.Equal(envelope, SyslogFrame.DecodeEnvelope(datagram));
    }

    [Theory]
    [InlineData("")]
    [InlineData("plain syslog line")]
    [InlineData("<13>Nov 18 13:39:07 sshd: bower-b64:!!not base64!!")]
    public void SyslogFrameRejectsOtherDatagrams(string datagram) =>
        Assert.Null(SyslogFrame.DecodeEnvelope(Encoding.ASCII.GetBytes(datagram)));

    [Theory]
    [InlineData("""{"schemaVersion":"1.0.0","eventId":"abc","nested":{"eventId":"no"}}""", "abc")]
    [InlineData("""{"nested":{"eventId":"no"},"eventId":"abc"}""", "abc")]
    [InlineData("""{"eventId":42}""", null)]
    [InlineData("""[1,2]""", null)]
    [InlineData("""not json""", null)]
    public void ReadEventIdReadsTheTopLevelId(string json, string? expected) =>
        Assert.Equal(expected, DevSinkStore.ReadEventId(Encoding.UTF8.GetBytes(json)));

    [Fact]
    public void StoreIsBounded()
    {
        DevSinkStore store = new();
        for (int index = 0; index < DevSinkStore.Capacity + 10; index++)
        {
            store.Add("http", $"e-{index}", "{}");
        }

        store.Add("http", "big", new string('x', DevSinkStore.MaximumRecordBytes + 1));

        Assert.Equal(DevSinkStore.Capacity, store.Records("http").Count);
        Assert.Equal(DevSinkStore.Capacity + 11, store.Summary().Received["http"]);
        Assert.False(store.Contains("e-0"));
        Assert.False(store.Contains("big"));
        Assert.True(store.Contains($"e-{DevSinkStore.Capacity + 9}"));
    }

    [Fact]
    public void S3ListPageFollowsContinuationOnlyWhenTruncated()
    {
        const string truncated = """
            <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsTruncated>true</IsTruncated>
            <Contents><Key>bower/a</Key></Contents><Contents><Key>bower/b</Key></Contents>
            <NextContinuationToken>next-1</NextContinuationToken></ListBucketResult>
            """;
        const string last = """
            <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsTruncated>false</IsTruncated>
            <Contents><Key>bower/c</Key></Contents></ListBucketResult>
            """;

        S3ListPage first = S3ListPage.Parse(truncated);
        S3ListPage final = S3ListPage.Parse(last);

        Assert.Equal(["bower/a", "bower/b"], first.Keys);
        Assert.Equal("next-1", first.NextContinuationToken);
        Assert.Equal(["bower/c"], final.Keys);
        Assert.Null(final.NextContinuationToken);
    }

    [Fact]
    public async Task S3ObjectLinesReadGzipAndPlain()
    {
        byte[] plain = Encoding.UTF8.GetBytes("{\"eventId\":\"a\"}\n\n{\"eventId\":\"b\"}\n");
        using MemoryStream compressed = new();
        await using (GZipStream gzip = new(compressed, CompressionLevel.Fastest, leaveOpen: true))
        {
            await gzip.WriteAsync(plain, TestContext.Current.CancellationToken);
        }

        Assert.Equal(2, (await S3ListPage.ReadLinesAsync(plain, TestContext.Current.CancellationToken)).Count);
        Assert.Equal(2, (await S3ListPage.ReadLinesAsync(compressed.ToArray(), TestContext.Current.CancellationToken)).Count);
        await Assert.ThrowsAnyAsync<InvalidDataException>(() =>
            S3ListPage.ReadLinesAsync([0x1f, 0x8b, 1, 2, 3], TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task S3ObjectLinesRejectOverLimitObjectsBeforeReturningAny()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        byte[] tooMany = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("{}\n", DevSinkStore.Capacity + 1)));
        byte[] longRecord = Encoding.UTF8.GetBytes(new string('x', DevSinkStore.MaximumRecordBytes + 1));
        using MemoryStream bomb = new();
        await using (GZipStream gzip = new(bomb, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            await gzip.WriteAsync(new byte[S3ListPage.MaximumDecodedBytes + 1], cancellationToken);
        }

        await Assert.ThrowsAsync<InvalidDataException>(() => S3ListPage.ReadLinesAsync(tooMany, cancellationToken));
        await Assert.ThrowsAsync<InvalidDataException>(() => S3ListPage.ReadLinesAsync(longRecord, cancellationToken));
        await Assert.ThrowsAsync<InvalidDataException>(() => S3ListPage.ReadLinesAsync(bomb.ToArray(), cancellationToken));
        // Two UTF-8 bytes per character: within the limit in characters, over it in bytes.
        byte[] multibyte = Encoding.UTF8.GetBytes(new string('é', (DevSinkStore.MaximumRecordBytes / 2) + 1));
        await Assert.ThrowsAsync<InvalidDataException>(() => S3ListPage.ReadLinesAsync(multibyte, cancellationToken));
        string atLimit = new('é', DevSinkStore.MaximumRecordBytes / 2);
        Assert.Equal([atLimit], await S3ListPage.ReadLinesAsync(Encoding.UTF8.GetBytes(atLimit + "\r\n"), cancellationToken));
        DevSinkStore store = new();
        store.Add("s3", null, atLimit);
        Assert.Single(store.Records("s3"));

        Assert.Equal(DevSinkStore.Capacity, (await S3ListPage.ReadLinesAsync(
            Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("{}\r\n", DevSinkStore.Capacity))), cancellationToken)).Count);
    }
}
