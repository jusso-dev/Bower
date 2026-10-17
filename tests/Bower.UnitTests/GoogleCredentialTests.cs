using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bower.Agent.Cloud.Gcp;
using Bower.Agent.Cloud.Gcp.Auth;

namespace Bower.UnitTests;

/// <summary>
/// In-house Google Application Default Credentials: metadata server, Workload Identity
/// Federation (file, URL and AWS sources, STS exchange, impersonation), lab-only key files,
/// and the refusals. All HTTP goes through fakes; no live cloud calls.
/// </summary>
public sealed class GoogleCredentialTests
{
    private const string Audience =
        "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/bower/providers/aws";

    private const string ImpersonationUrl =
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/bower@bower-prod.iam.gserviceaccount.com:generateAccessToken";

    private const string PubSubScope = "https://www.googleapis.com/auth/pubsub";

    private static readonly DateTimeOffset Now = new(2020, 2, 28, 22, 50, 5, TimeSpan.Zero);

    // ---- AWS Signature Version 4: AWS's published test suite (aws-c-auth aws-signing-test-suite/v4).

    private static readonly AwsCredentials SuiteCredentials = new("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", null);

    private static readonly DateTimeOffset SuiteTime = new(2015, 8, 30, 12, 36, 0, TimeSpan.Zero);

    [Theory]
    [InlineData("get-vanilla", "GET", "/", "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")]
    [InlineData("get-vanilla-query-order-key-case", "GET", "/?Param2=value2&Param1=value1", "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500")]
    [InlineData(
        "get-vanilla-query-unreserved",
        "GET",
        "/?-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "9c3e54bfcdf0b19771a7f523ee5669cdf59bc7cc0884027167c21bb143a40197")]
    [InlineData("post-vanilla", "POST", "/", "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b")]
    [InlineData("post-vanilla-query", "POST", "/?Param1=value1", "28038455d6de14eafc1f9222cf5aa6f1a96197d7deb8263271d420d138af7f11")]
    public void SigV4_MatchesAwsTestSuite(string name, string method, string pathAndQuery, string expected)
    {
        AwsSignedRequest signed = AwsSignatureV4.Sign(
            method,
            new Uri("https://example.amazonaws.com" + pathAndQuery),
            [],
            [],
            SuiteCredentials,
            "us-east-1",
            "service",
            SuiteTime);

        Assert.True(expected == signed.Signature, name);
        Assert.Equal(
            $"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature={expected}",
            signed.Authorization);
    }

    [Fact]
    public void SigV4_MatchesAwsTestSuite_CanonicalRequest()
    {
        AwsSignedRequest signed = AwsSignatureV4.Sign(
            "GET",
            new Uri("https://example.amazonaws.com/?Param2=value2&Param1=value1"),
            [],
            [],
            SuiteCredentials,
            "us-east-1",
            "service",
            SuiteTime);

        Assert.Equal(
            "GET\n/\nParam1=value1&Param2=value2\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\n"
            + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            signed.CanonicalRequest);
    }

    [Theory]
    [InlineData("6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267", "07ec1639c89043aa0e3e2de82b96708f198cceab042d4a97044c66dd9f74e7f8", "GET")]
    [InlineData(
        "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==",
        "85d96828115b5dc0cfc3bd16ad9e210dd772bbebba041836c64533a82be05ead",
        "POST")]
    public void SigV4_SignsSessionToken_AwsTestSuite(string token, string expected, string method)
    {
        // get-vanilla-with-session-token and post-sts-header-before.
        AwsSignedRequest signed = AwsSignatureV4.Sign(
            method,
            new Uri("https://example.amazonaws.com/"),
            [],
            [],
            SuiteCredentials with { SessionToken = token },
            "us-east-1",
            "service",
            SuiteTime);

        Assert.Equal(expected, signed.Signature);
        Assert.Contains("SignedHeaders=host;x-amz-date;x-amz-security-token,", signed.Authorization, StringComparison.Ordinal);
    }

    [Fact]
    public void SigV4_SignsExtraHeadersAndBody_AwsTestSuite()
    {
        // post-header-key-sort.
        AwsSignedRequest sorted = AwsSignatureV4.Sign(
            "POST",
            new Uri("https://example.amazonaws.com/"),
            [new("My-Header1", "value1")],
            [],
            SuiteCredentials,
            "us-east-1",
            "service",
            SuiteTime);
        // post-x-www-form-urlencoded (signed body).
        AwsSignedRequest form = AwsSignatureV4.Sign(
            "POST",
            new Uri("https://example.amazonaws.com/"),
            [
                new("Content-Type", "application/x-www-form-urlencoded"),
                new("Content-Length", "13"),
                new("x-amz-content-sha256", "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e")
            ],
            "Param1=value1"u8,
            SuiteCredentials,
            "us-east-1",
            "service",
            SuiteTime);

        Assert.Equal("c5410059b04c1ee005303aed430f6e6645f61f4dc9e1461ec8f8916fdf18852c", sorted.Signature);
        Assert.Equal("d3875051da38690788ef43de4db0d8f280229d82040bfac253562e56c3f20e0b", form.Signature);
    }

    [Fact]
    public void SigV4_RefusesPathsThatNeedEncoding() =>
        Assert.Throws<InvalidOperationException>(() => AwsSignatureV4.Sign(
            "GET",
            new Uri("https://example.amazonaws.com/a%20b"),
            [],
            [],
            SuiteCredentials,
            "us-east-1",
            "service",
            SuiteTime));

    // ---- Metadata server (GKE Workload Identity, attached service accounts).

    [Fact]
    public async Task Metadata_FetchesScopedTokenAndCachesUntilNearExpiry()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        FakeClock clock = new(Now);
        int issued = 0;
        FakeHttp http = new(request => request.RequestUri!.AbsolutePath switch
        {
            "/" => Metadata(HttpStatusCode.OK, string.Empty),
            "/computeMetadata/v1/instance/service-accounts/default/token" =>
                Metadata(HttpStatusCode.OK, Token($"metadata-token-{++issued}", 3599)),
            _ => new HttpResponseMessage(HttpStatusCode.NotFound)
        });
        using GoogleAccessTokenSource tokens = Source(http, clock, new Dictionary<string, string>());

        string first = await tokens.GetAccessTokenAsync(cancellationToken);
        string cached = await tokens.GetAccessTokenAsync(cancellationToken);
        clock.Advance(TimeSpan.FromMinutes(54));
        string stillCached = await tokens.GetAccessTokenAsync(cancellationToken);
        clock.Advance(TimeSpan.FromMinutes(1));
        string refreshed = await tokens.GetAccessTokenAsync(cancellationToken);

        Assert.Equal(["metadata-token-1", "metadata-token-1", "metadata-token-1", "metadata-token-2"], [first, cached, stillCached, refreshed]);
        Recorded probe = http.Requests[0];
        Assert.Equal("http://169.254.169.254/", probe.Url);
        Recorded token = http.Requests[1];
        Assert.Equal(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fpubsub",
            token.Url);
        Assert.All(http.Requests, request => Assert.Equal("Google", request.Header("Metadata-Flavor")));
        Assert.Equal(3, http.Requests.Count);
    }

    [Fact]
    public async Task Metadata_HonoursGceMetadataHost()
    {
        FakeHttp http = new(request => Metadata(
            HttpStatusCode.OK,
            request.RequestUri!.AbsolutePath == "/" ? string.Empty : Token("emulator-token", 3599)));
        using GoogleAccessTokenSource tokens = Source(
            http,
            new FakeClock(Now),
            new Dictionary<string, string> { ["GCE_METADATA_HOST"] = "127.0.0.1:8085" });

        Assert.Equal("emulator-token", await tokens.GetAccessTokenAsync(TestContext.Current.CancellationToken));
        Assert.All(http.Requests, request => Assert.StartsWith("http://127.0.0.1:8085/", request.Url, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Metadata_RefusesResponseWithoutMetadataFlavor()
    {
        FakeHttp http = new(request => request.RequestUri!.AbsolutePath == "/"
            ? Metadata(HttpStatusCode.OK, string.Empty)
            : Json(HttpStatusCode.OK, Token("spoofed", 3599)));
        using GoogleAccessTokenSource tokens = Source(http, new FakeClock(Now), new Dictionary<string, string>());

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => tokens.GetAccessTokenAsync(TestContext.Current.CancellationToken));
        Assert.Contains("Metadata-Flavor", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Metadata_RefusesNonMetadataHostOverride()
    {
        using GoogleAccessTokenSource tokens = Source(
            new FakeHttp(_ => Metadata(HttpStatusCode.OK, string.Empty)),
            new FakeClock(Now),
            new Dictionary<string, string> { ["GCE_METADATA_HOST"] = "attacker.example" });

        await Assert.ThrowsAsync<InvalidOperationException>(() => tokens.InitializeAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Discovery_FailsClosedWithoutAnyCredentials()
    {
        FakeHttp http = new(_ => throw new HttpRequestException("no route to host"));
        using GoogleAccessTokenSource tokens = Source(http, new FakeClock(Now), new Dictionary<string, string>());

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => tokens.InitializeAsync(TestContext.Current.CancellationToken));
        Assert.Contains("No Google Application Default Credentials", error.Message, StringComparison.Ordinal);
        Assert.Equal(3, http.Requests.Count);
    }

    // ---- Refusals and malformed input.

    [Fact]
    public async Task KeyFile_RefusedByDefaultAndAllowedForLab()
    {
        using TemporaryDirectory directory = new();
        using RSA rsa = RSA.Create(2048);
        string path = Write(directory, "key.json", ServiceAccountKey(rsa));
        Dictionary<string, string> environment = new() { ["GOOGLE_APPLICATION_CREDENTIALS"] = path };
        FakeHttp http = new(_ => Json(HttpStatusCode.OK, Token("key-token", 3600)));
        using GoogleAccessTokenSource refused = Source(http, new FakeClock(Now), environment);
        using GoogleAccessTokenSource allowed = Source(http, new FakeClock(Now), environment, allowKeyFile: true);

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => refused.InitializeAsync(TestContext.Current.CancellationToken));
        string token = await allowed.GetAccessTokenAsync(TestContext.Current.CancellationToken);

        Assert.Contains("BOWER_GCP_ALLOW_KEY_FILE", error.Message, StringComparison.Ordinal);
        Assert.Equal("key-token", token);
        Recorded request = Assert.Single(http.Requests);
        Assert.Equal("https://oauth2.googleapis.com/token", request.Url);
        Dictionary<string, string> form = Form(request.Body);
        Assert.Equal("urn:ietf:params:oauth:grant-type:jwt-bearer", form["grant_type"]);
        string[] jwt = form["assertion"].Split('.');
        Assert.True(rsa.VerifyData(
            Encoding.ASCII.GetBytes(jwt[0] + "." + jwt[1]),
            Base64Url(jwt[2]),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1));
        using JsonDocument claims = JsonDocument.Parse(Base64Url(jwt[1]));
        Assert.Equal("bower@bower-prod.iam.gserviceaccount.com", claims.RootElement.GetProperty("iss").GetString());
        Assert.Equal(PubSubScope, claims.RootElement.GetProperty("scope").GetString());
        Assert.Equal("https://oauth2.googleapis.com/token", claims.RootElement.GetProperty("aud").GetString());
    }

    [Fact]
    public async Task WellKnownGcloudFile_ServiceAccountKeyIsRefused()
    {
        using TemporaryDirectory directory = new();
        using RSA rsa = RSA.Create(2048);
        Write(directory, "application_default_credentials.json", ServiceAccountKey(rsa));
        FakeHttp http = new(_ => Metadata(HttpStatusCode.OK, string.Empty));
        using GoogleAccessTokenSource tokens = Source(
            http,
            new FakeClock(Now),
            new Dictionary<string, string> { ["CLOUDSDK_CONFIG"] = directory.Path });

        await Assert.ThrowsAsync<InvalidOperationException>(() => tokens.InitializeAsync(TestContext.Current.CancellationToken));
        Assert.Empty(http.Requests);
    }

    [Fact]
    public async Task UserCredentials_RefusedByDefault()
    {
        using TemporaryDirectory directory = new();
        string path = Write(
            directory,
            "adc.json",
            """{"type":"authorized_user","client_id":"id","client_secret":"secret","refresh_token":"refresh-secret"}""");
        FakeHttp http = new(_ => Json(HttpStatusCode.OK, Token("user-token", 3600)));
        Dictionary<string, string> environment = new() { ["GOOGLE_APPLICATION_CREDENTIALS"] = path };
        using GoogleAccessTokenSource refused = Source(http, new FakeClock(Now), environment);
        using GoogleAccessTokenSource allowed = Source(http, new FakeClock(Now), environment, allowKeyFile: true);

        await Assert.ThrowsAsync<InvalidOperationException>(() => refused.InitializeAsync(TestContext.Current.CancellationToken));
        Assert.Equal("user-token", await allowed.GetAccessTokenAsync(TestContext.Current.CancellationToken));
        Assert.Equal("refresh_token", Form(Assert.Single(http.Requests).Body)["grant_type"]);
    }

    [Theory]
    [InlineData("{\"type\":\"external_account\",\"audience\":")]
    [InlineData("not json at all secret-material")]
    [InlineData("{\"type\":\"external_account\",\"audience\":42}")]
    [InlineData("{\"type\":\"impersonated_service_account\"}")]
    [InlineData("{\"type\":\"gdch_service_account\"}")]
    [InlineData("{}")]
    public async Task MalformedOrUnsupportedCredentialFile_IsRefusedWithoutEchoingContent(string json)
    {
        using TemporaryDirectory directory = new();
        string path = Write(directory, "adc.json", json);
        using GoogleAccessTokenSource tokens = Source(
            new FakeHttp(_ => throw new InvalidOperationException("no HTTP expected")),
            new FakeClock(Now),
            new Dictionary<string, string> { ["GOOGLE_APPLICATION_CREDENTIALS"] = path });

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => tokens.InitializeAsync(TestContext.Current.CancellationToken));
        Assert.DoesNotContain("secret-material", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OversizeCredentialFile_IsRefused()
    {
        using TemporaryDirectory directory = new();
        string path = Write(directory, "adc.json", "{\"type\":\"external_account\",\"pad\":\"" + new string('a', 70_000) + "\"}");
        using GoogleAccessTokenSource tokens = Source(
            new FakeHttp(_ => throw new InvalidOperationException("no HTTP expected")),
            new FakeClock(Now),
            new Dictionary<string, string> { ["GOOGLE_APPLICATION_CREDENTIALS"] = path });

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => tokens.InitializeAsync(TestContext.Current.CancellationToken));
        Assert.Contains("exceeds", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingCredentialFile_IsRefused()
    {
        using GoogleAccessTokenSource tokens = Source(
            new FakeHttp(_ => Metadata(HttpStatusCode.OK, string.Empty)),
            new FakeClock(Now),
            new Dictionary<string, string> { ["GOOGLE_APPLICATION_CREDENTIALS"] = "/nonexistent/bower/adc.json" });

        await Assert.ThrowsAsync<InvalidOperationException>(() => tokens.InitializeAsync(TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("audience", "https://attacker.example/pool")]
    [InlineData("audience", "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p")]
    [InlineData("token_url", "https://attacker.example/v1/token")]
    [InlineData("token_url", "http://sts.googleapis.com/v1/token")]
    [InlineData("token_url", "https://sts.googleapis.com.attacker.example/v1/token")]
    [InlineData("service_account_impersonation_url", "https://attacker.example/v1/x:generateAccessToken")]
    [InlineData("service_account_impersonation_url", "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/x:signJwt")]
    [InlineData("subject_token_type", "urn:ietf:params:aws:token-type:aws4_request")]
    [InlineData("subject_token_type", "urn:ietf:params:oauth:token-type:mtls")]
    public async Task ExternalAccount_RefusesUnsafeConfiguration(string field, string value)
    {
        using TemporaryDirectory directory = new();
        string token = Write(directory, "subject", "subject-jwt");
        Dictionary<string, object?> config = ExternalAccount(new Dictionary<string, object?> { ["file"] = token });
        config[field] = value;
        using GoogleAccessTokenSource tokens = FileSource(directory, config, new FakeHttp(_ => Json(HttpStatusCode.OK, StsToken("x"))));

        await Assert.ThrowsAsync<InvalidOperationException>(() => tokens.InitializeAsync(TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(599)]
    [InlineData(43201)]
    public async Task ExternalAccount_RefusesOutOfRangeLifetime(int seconds)
    {
        using TemporaryDirectory directory = new();
        Dictionary<string, object?> config = ExternalAccount(new Dictionary<string, object?> { ["file"] = Write(directory, "subject", "jwt") });
        config["service_account_impersonation"] = new Dictionary<string, object?> { ["token_lifetime_seconds"] = seconds };
        using GoogleAccessTokenSource tokens = FileSource(directory, config, new FakeHttp(_ => Json(HttpStatusCode.OK, StsToken("x"))));

        await Assert.ThrowsAsync<InvalidOperationException>(() => tokens.InitializeAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ExternalAccount_RefusesExecutableSourceEvenWhenAllowedByEnvironment()
    {
        using TemporaryDirectory directory = new();
        Dictionary<string, object?> config = ExternalAccount(new Dictionary<string, object?>
        {
            ["executable"] = new Dictionary<string, object?> { ["command"] = "/bin/echo token" }
        });
        string path = Write(directory, "adc.json", JsonSerializer.Serialize(config, TestJson.Default.DictionaryStringObject));
        using GoogleAccessTokenSource tokens = Source(
            new FakeHttp(_ => throw new InvalidOperationException("no HTTP expected")),
            new FakeClock(Now),
            new Dictionary<string, string>
            {
                ["GOOGLE_APPLICATION_CREDENTIALS"] = path,
                ["GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES"] = "1"
            });

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => tokens.InitializeAsync(TestContext.Current.CancellationToken));
        Assert.Contains("Executable", error.Message, StringComparison.Ordinal);
    }

    // ---- Workload Identity Federation: file and URL sources.

    [Fact]
    public async Task ExternalAccount_FileSource_ExchangesAndImpersonates()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        using TemporaryDirectory directory = new();
        string subject = Write(directory, "token", "header.payload.signature\n");
        Dictionary<string, object?> config = ExternalAccount(new Dictionary<string, object?> { ["file"] = subject });
        config["service_account_impersonation_url"] = ImpersonationUrl;
        config["service_account_impersonation"] = new Dictionary<string, object?> { ["token_lifetime_seconds"] = 1800 };
        FakeHttp http = new(request => request.RequestUri!.Host switch
        {
            "sts.googleapis.com" => Json(HttpStatusCode.OK, StsToken("federated-token")),
            "iamcredentials.googleapis.com" => Json(
                HttpStatusCode.OK,
                """{"accessToken":"impersonated-token","expireTime":"2020-02-28T23:20:05Z"}"""),
            _ => new HttpResponseMessage(HttpStatusCode.NotFound)
        });
        FakeClock clock = new(Now);
        using GoogleAccessTokenSource tokens = FileSource(directory, config, http, clock);

        string token = await tokens.GetAccessTokenAsync(cancellationToken);
        clock.Advance(TimeSpan.FromMinutes(24));
        string cached = await tokens.GetAccessTokenAsync(cancellationToken);

        Assert.Equal("impersonated-token", token);
        Assert.Equal("impersonated-token", cached);
        Assert.Equal(2, http.Requests.Count);
        Recorded sts = http.Requests[0];
        Assert.Equal("POST", sts.Method);
        Assert.Equal("https://sts.googleapis.com/v1/token", sts.Url);
        Assert.Equal("application/x-www-form-urlencoded", sts.ContentType);
        Assert.Equal(
            new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
                ["audience"] = Audience,
                ["scope"] = "https://www.googleapis.com/auth/cloud-platform",
                ["requested_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
                ["subject_token"] = "header.payload.signature",
                ["subject_token_type"] = "urn:ietf:params:oauth:token-type:jwt"
            },
            Form(sts.Body));
        Assert.Null(sts.Header("Authorization"));
        Recorded iam = http.Requests[1];
        Assert.Equal(ImpersonationUrl, iam.Url);
        Assert.Equal("Bearer federated-token", iam.Header("Authorization"));
        using JsonDocument body = JsonDocument.Parse(iam.Body);
        Assert.Equal(PubSubScope, body.RootElement.GetProperty("scope")[0].GetString());
        Assert.Equal("1800s", body.RootElement.GetProperty("lifetime").GetString());

        // Five minutes before expireTime the token is refreshed.
        clock.Advance(TimeSpan.FromMinutes(1));
        await tokens.GetAccessTokenAsync(cancellationToken);
        Assert.Equal(4, http.Requests.Count);
    }

    [Fact]
    public async Task ExternalAccount_FileSourceJson_WithoutImpersonationUsesStsTokenAndClientAuth()
    {
        using TemporaryDirectory directory = new();
        string subject = Write(directory, "token.json", """{"id_token":"oidc-jwt","other":1}""");
        Dictionary<string, object?> config = ExternalAccount(new Dictionary<string, object?>
        {
            ["file"] = subject,
            ["format"] = new Dictionary<string, object?> { ["type"] = "json", ["subject_token_field_name"] = "id_token" }
        });
        config["client_id"] = "client";
        config["client_secret"] = "secret";
        FakeHttp http = new(_ => Json(HttpStatusCode.OK, StsToken("sts-token")));
        using GoogleAccessTokenSource tokens = FileSource(directory, config, http);

        Assert.Equal("sts-token", await tokens.GetAccessTokenAsync(TestContext.Current.CancellationToken));
        Recorded sts = Assert.Single(http.Requests);
        Dictionary<string, string> form = Form(sts.Body);
        Assert.Equal("oidc-jwt", form["subject_token"]);
        Assert.Equal(PubSubScope, form["scope"]);
        Assert.Equal("Basic " + Convert.ToBase64String("client:secret"u8.ToArray()), sts.Header("Authorization"));
    }

    [Fact]
    public async Task ExternalAccount_UrlSource_SendsHeadersAndReadsJsonField()
    {
        using TemporaryDirectory directory = new();
        Dictionary<string, object?> config = ExternalAccount(new Dictionary<string, object?>
        {
            ["url"] = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=x",
            ["headers"] = new Dictionary<string, object?> { ["Metadata"] = "True" },
            ["format"] = new Dictionary<string, object?> { ["type"] = "json", ["subject_token_field_name"] = "access_token" }
        });
        FakeHttp http = new(request => request.RequestUri!.Host == "169.254.169.254"
            ? Json(HttpStatusCode.OK, """{"access_token":"azure-jwt"}""")
            : Json(HttpStatusCode.OK, StsToken("sts-token")));
        using GoogleAccessTokenSource tokens = FileSource(directory, config, http);

        Assert.Equal("sts-token", await tokens.GetAccessTokenAsync(TestContext.Current.CancellationToken));
        Assert.Equal("True", http.Requests[0].Header("Metadata"));
        Assert.Equal("GET", http.Requests[0].Method);
        Assert.Equal("azure-jwt", Form(http.Requests[1].Body)["subject_token"]);
    }

    [Theory]
    [InlineData("http://token-server.internal/token")]
    [InlineData("ftp://169.254.169.254/token")]
    public async Task ExternalAccount_UrlSource_RefusesCleartextToNonLocalHosts(string url)
    {
        using TemporaryDirectory directory = new();
        Dictionary<string, object?> config = ExternalAccount(new Dictionary<string, object?> { ["url"] = url });
        using GoogleAccessTokenSource tokens = FileSource(directory, config, new FakeHttp(_ => Json(HttpStatusCode.OK, "x")));

        await Assert.ThrowsAsync<InvalidOperationException>(() => tokens.InitializeAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ExternalAccount_UrlSource_RefusesRedirects()
    {
        using TemporaryDirectory directory = new();
        Dictionary<string, object?> config = ExternalAccount(new Dictionary<string, object?> { ["url"] = "https://idp.example/token" });
        FakeHttp http = new(_ =>
        {
            HttpResponseMessage redirect = new(HttpStatusCode.Found);
            redirect.Headers.Location = new Uri("https://attacker.example/");
            return redirect;
        });
        using GoogleAccessTokenSource tokens = FileSource(directory, config, http);

        HttpRequestException error = await Assert.ThrowsAsync<HttpRequestException>(
            () => tokens.GetAccessTokenAsync(TestContext.Current.CancellationToken));
        Assert.Equal(HttpStatusCode.Found, error.StatusCode);
        Assert.Single(http.Requests);
    }

    [Fact]
    public async Task ExternalAccount_RefusesOversizeResponses()
    {
        using TemporaryDirectory directory = new();
        Dictionary<string, object?> config = ExternalAccount(new Dictionary<string, object?> { ["file"] = Write(directory, "t", "jwt") });
        string huge = "{\"access_token\":\"" + new string('a', 70_000) + "\",\"token_type\":\"Bearer\",\"expires_in\":3600}";
        using GoogleAccessTokenSource declared = FileSource(directory, config, new FakeHttp(_ => Json(HttpStatusCode.OK, huge)));
        using GoogleAccessTokenSource chunked = FileSource(directory, config, new FakeHttp(_ =>
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new UnknownLengthStream(Encoding.UTF8.GetBytes(huge))) }));

        InvalidOperationException first = await Assert.ThrowsAsync<InvalidOperationException>(
            () => declared.GetAccessTokenAsync(TestContext.Current.CancellationToken));
        InvalidOperationException second = await Assert.ThrowsAsync<InvalidOperationException>(
            () => chunked.GetAccessTokenAsync(TestContext.Current.CancellationToken));
        Assert.Contains("exceeds", first.Message, StringComparison.Ordinal);
        Assert.Contains("exceeds", second.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{"access_token":"t","token_type":"MAC","expires_in":3600}""")]
    [InlineData("""{"access_token":"t","token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:id_token","expires_in":3600}""")]
    [InlineData("""{"access_token":"","token_type":"Bearer","expires_in":3600}""")]
    [InlineData("""{"access_token":"t","token_type":"Bearer"}""")]
    [InlineData("""{"access_token":"t","token_type":"Bearer","expires_in":-5}""")]
    [InlineData("""{"access_token":"t","token_type":"Bearer","expires_in":"soon"}""")]
    [InlineData("""[1,2,3]""")]
    public async Task ExternalAccount_RefusesWrongTokenResponses(string response)
    {
        using TemporaryDirectory directory = new();
        Dictionary<string, object?> config = ExternalAccount(new Dictionary<string, object?> { ["file"] = Write(directory, "t", "jwt") });
        using GoogleAccessTokenSource tokens = FileSource(directory, config, new FakeHttp(_ => Json(HttpStatusCode.OK, response)));

        await Assert.ThrowsAsync<InvalidOperationException>(() => tokens.GetAccessTokenAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ExternalAccount_StsErrorReportsCodeButNotBody()
    {
        using TemporaryDirectory directory = new();
        Dictionary<string, object?> config = ExternalAccount(new Dictionary<string, object?> { ["file"] = Write(directory, "t", "jwt") });
        FakeHttp http = new(_ => Json(
            HttpStatusCode.BadRequest,
            """{"error":"invalid_grant","error_description":"subject token secret-subject is expired"}"""));
        using GoogleAccessTokenSource tokens = FileSource(directory, config, http);

        HttpRequestException error = await Assert.ThrowsAsync<HttpRequestException>(
            () => tokens.GetAccessTokenAsync(TestContext.Current.CancellationToken));
        Assert.Contains("400 (invalid_grant)", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-subject", error.Message, StringComparison.Ordinal);
    }

    // ---- Workload Identity Federation: AWS source.

    [Fact]
    public async Task ExternalAccount_Aws_Imdsv2SignsGetCallerIdentity()
    {
        using TemporaryDirectory directory = new();
        Dictionary<string, object?> config = ExternalAccount(AwsSource(imdsv2: true));
        config["subject_token_type"] = "urn:ietf:params:aws:token-type:aws4_request";
        FakeHttp http = new(request => (request.Method.Method, request.RequestUri!.AbsolutePath) switch
        {
            ("PUT", "/latest/api/token") => Text("imds-session"),
            ("GET", "/latest/meta-data/placement/availability-zone") => Text("us-east-2b"),
            ("GET", "/latest/meta-data/iam/security-credentials") => Text("bower-role"),
            ("GET", "/latest/meta-data/iam/security-credentials/bower-role") => Json(
                HttpStatusCode.OK,
                """{"Code":"Success","AccessKeyId":"AKIDEXAMPLE","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY","Token":"session-token-example"}"""),
            ("POST", "/v1/token") => Json(HttpStatusCode.OK, StsToken("aws-federated")),
            _ => new HttpResponseMessage(HttpStatusCode.NotFound)
        });
        using GoogleAccessTokenSource tokens = FileSource(directory, config, http);

        Assert.Equal("aws-federated", await tokens.GetAccessTokenAsync(TestContext.Current.CancellationToken));

        Assert.Equal("300", http.Requests[0].Header("X-aws-ec2-metadata-token-ttl-seconds"));
        Assert.All(http.Requests.Skip(1).Take(3), request => Assert.Equal("imds-session", request.Header("X-aws-ec2-metadata-token")));
        Dictionary<string, string> form = Form(http.Requests[4].Body);
        Assert.Equal("urn:ietf:params:aws:token-type:aws4_request", form["subject_token_type"]);
        using JsonDocument subject = JsonDocument.Parse(Uri.UnescapeDataString(form["subject_token"]));
        JsonElement root = subject.RootElement;
        Assert.Equal("https://sts.us-east-2.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15", root.GetProperty("url").GetString());
        Assert.Equal("POST", root.GetProperty("method").GetString());
        Dictionary<string, string> headers = root.GetProperty("headers").EnumerateArray()
            .ToDictionary(item => item.GetProperty("key").GetString()!, item => item.GetProperty("value").GetString()!);
        Assert.Equal(["Authorization", "host", "x-amz-date", "x-amz-security-token", "x-goog-cloud-target-resource"], headers.Keys);
        Assert.Equal("sts.us-east-2.amazonaws.com", headers["host"]);
        Assert.Equal("20200228T225005Z", headers["x-amz-date"]);
        Assert.Equal("session-token-example", headers["x-amz-security-token"]);
        Assert.Equal(Audience, headers["x-goog-cloud-target-resource"]);
        // Independently computed reference signature for this request.
        Assert.Equal(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20200228/us-east-2/sts/aws4_request, "
            + "SignedHeaders=host;x-amz-date;x-amz-security-token;x-goog-cloud-target-resource, "
            + "Signature=6e8ff1b9a5090838eb1b5189e2c5e4455ce31748816934b12f8904f3df47f987",
            headers["Authorization"]);
    }

    [Fact]
    public async Task ExternalAccount_Aws_EnvironmentSkipsMetadataServer()
    {
        using TemporaryDirectory directory = new();
        Dictionary<string, object?> config = ExternalAccount(AwsSource(imdsv2: true));
        config["subject_token_type"] = "urn:ietf:params:aws:token-type:aws4_request";
        string path = Write(directory, "adc.json", JsonSerializer.Serialize(config, TestJson.Default.DictionaryStringObject));
        FakeHttp http = new(_ => Json(HttpStatusCode.OK, StsToken("aws-federated")));
        using GoogleAccessTokenSource tokens = Source(http, new FakeClock(Now), new Dictionary<string, string>
        {
            ["GOOGLE_APPLICATION_CREDENTIALS"] = path,
            ["AWS_DEFAULT_REGION"] = "us-east-2",
            ["AWS_ACCESS_KEY_ID"] = "AKIDEXAMPLE",
            ["AWS_SECRET_ACCESS_KEY"] = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            ["AWS_SESSION_TOKEN"] = "session-token-example"
        });

        await tokens.GetAccessTokenAsync(TestContext.Current.CancellationToken);

        Recorded sts = Assert.Single(http.Requests);
        Assert.Contains(
            "Signature%3D6e8ff1b9a5090838eb1b5189e2c5e4455ce31748816934b12f8904f3df47f987",
            Form(sts.Body)["subject_token"],
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("url", "http://attacker.example/latest/meta-data/iam/security-credentials")]
    [InlineData("region_url", "https://169.254.169.254.attacker.example/az")]
    [InlineData("imdsv2_session_token_url", "http://10.0.0.1/latest/api/token")]
    [InlineData("environment_id", "aws2")]
    [InlineData("environment_id", "azure1")]
    [InlineData("regional_cred_verification_url", "http://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15")]
    public async Task ExternalAccount_Aws_RefusesUnsafeSource(string field, string value)
    {
        using TemporaryDirectory directory = new();
        Dictionary<string, object?> source = AwsSource(imdsv2: true);
        source[field] = value;
        Dictionary<string, object?> config = ExternalAccount(source);
        config["subject_token_type"] = "urn:ietf:params:aws:token-type:aws4_request";
        using GoogleAccessTokenSource tokens = FileSource(directory, config, new FakeHttp(_ => Text("x")));

        await Assert.ThrowsAsync<InvalidOperationException>(() => tokens.InitializeAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ExternalAccount_Aws_RequiresAwsSubjectTokenType()
    {
        using TemporaryDirectory directory = new();
        using GoogleAccessTokenSource tokens = FileSource(
            directory,
            ExternalAccount(AwsSource(imdsv2: false)),
            new FakeHttp(_ => Text("x")));

        await Assert.ThrowsAsync<InvalidOperationException>(() => tokens.InitializeAsync(TestContext.Current.CancellationToken));
    }

    // ---- Helpers.

    private static GoogleAccessTokenSource Source(
        FakeHttp http,
        TimeProvider clock,
        Dictionary<string, string> environment,
        bool allowKeyFile = false)
    {
        // No HOME: the developer's own gcloud file must never be read by tests.
        environment.TryAdd("HOME", "/nonexistent/bower-test-home");
        return new GoogleAccessTokenSource(
            allowKeyFile,
            name => environment.GetValueOrDefault(name),
            new GoogleAuthHttp(http, http, disposeHandlers: false),
            clock);
    }

    private static GoogleAccessTokenSource FileSource(
        TemporaryDirectory directory,
        Dictionary<string, object?> config,
        FakeHttp http,
        FakeClock? clock = null)
    {
        string path = Write(directory, "adc.json", JsonSerializer.Serialize(config, TestJson.Default.DictionaryStringObject));
        return Source(http, clock ?? new FakeClock(Now), new Dictionary<string, string> { ["GOOGLE_APPLICATION_CREDENTIALS"] = path });
    }

    private static Dictionary<string, object?> ExternalAccount(Dictionary<string, object?> source) =>
        new()
        {
            ["type"] = "external_account",
            ["audience"] = Audience,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:jwt",
            ["token_url"] = "https://sts.googleapis.com/v1/token",
            ["credential_source"] = source
        };

    private static Dictionary<string, object?> AwsSource(bool imdsv2)
    {
        Dictionary<string, object?> source = new()
        {
            ["environment_id"] = "aws1",
            ["region_url"] = "http://169.254.169.254/latest/meta-data/placement/availability-zone",
            ["url"] = "http://169.254.169.254/latest/meta-data/iam/security-credentials",
            ["regional_cred_verification_url"] = "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15"
        };
        if (imdsv2)
        {
            source["imdsv2_session_token_url"] = "http://169.254.169.254/latest/api/token";
        }

        return source;
    }

    private static string ServiceAccountKey(RSA rsa) => JsonSerializer.Serialize(
        new Dictionary<string, object?>
        {
            ["type"] = "service_account",
            ["client_email"] = "bower@bower-prod.iam.gserviceaccount.com",
            ["private_key_id"] = "key-1",
            ["private_key"] = rsa.ExportPkcs8PrivateKeyPem(),
            ["token_uri"] = "https://oauth2.googleapis.com/token"
        },
        TestJson.Default.DictionaryStringObject);

    private static string Write(TemporaryDirectory directory, string name, string content)
    {
        string path = Path.Combine(directory.Path, name);
        File.WriteAllText(path, content);
        return path;
    }

    private static string Token(string value, int expiresIn) =>
        $$"""{"access_token":"{{value}}","expires_in":{{expiresIn}},"token_type":"Bearer"}""";

    private static string StsToken(string value) =>
        $$"""{"access_token":"{{value}}","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}""";

    private static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static HttpResponseMessage Text(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "text/plain") };

    private static HttpResponseMessage Metadata(HttpStatusCode status, string body)
    {
        HttpResponseMessage response = Json(status, body);
        response.Headers.Add("Metadata-Flavor", "Google");
        return response;
    }

    private static Dictionary<string, string> Form(string body) =>
        body.Split('&').Select(pair => pair.Split('=', 2)).ToDictionary(
            pair => WebUtility.UrlDecode(pair[0]),
            pair => WebUtility.UrlDecode(pair[1]));

    private static byte[] Base64Url(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded.PadRight(padded.Length + ((4 - (padded.Length % 4)) % 4), '='));
    }

    internal sealed record Recorded(string Method, string Url, Dictionary<string, string> Headers, string? ContentType, string Body)
    {
        public string? Header(string name) => Headers.GetValueOrDefault(name);
    }

    private sealed class FakeHttp(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<Recorded> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
            Requests.Add(new Recorded(
                request.Method.Method,
                request.RequestUri!.AbsoluteUri,
                request.Headers.ToDictionary(item => item.Key, item => string.Join(",", item.Value), StringComparer.OrdinalIgnoreCase),
                request.Content?.Headers.ContentType?.MediaType,
                body));
            return respond(request);
        }
    }

    /// <summary>A stream that hides its length, like a chunked response.</summary>
    private sealed class UnknownLengthStream(byte[] content) : MemoryStream(content)
    {
        public override bool CanSeek => false;
    }
}

[System.Text.Json.Serialization.JsonSerializable(typeof(Dictionary<string, object?>))]
[System.Text.Json.Serialization.JsonSerializable(typeof(Dictionary<string, string>))]
[System.Text.Json.Serialization.JsonSerializable(typeof(int))]
[System.Text.Json.Serialization.JsonSerializable(typeof(string))]
internal sealed partial class TestJson : System.Text.Json.Serialization.JsonSerializerContext;
