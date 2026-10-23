using Bower.Redaction.Detectors;
using Bower.Redaction.Detectors.Australian;
using Bower.Redaction.Detectors.Classification;
using Bower.Redaction.Detectors.Crypto;
using Bower.Redaction.Detectors.Financial;
using Bower.Redaction.Detectors.Identity;
using Bower.Redaction.Detectors.Secrets;

namespace Bower.Redaction.Privacy;

/// <summary>
/// Built-in detector modules. Custom detectors can be appended without modifying the engine.
/// </summary>
public static class DetectorCatalog
{
    public static IReadOnlyList<ISensitiveDetector> CreateDefaultValueDetectors() =>
    [
        // Australian
        new TfnDetector(),
        new CrnDetector(),
        new MedicareDetector(),
        new IhiDetector(),
        new PassportDetector(),
        new DriverLicenceDetector(),
        new AbnDetector(),
        new AcnDetector(),
        new DvaDetector(),
        // Financial
        new CreditCardDetector(),
        new BsbAccountDetector(),
        new IbanDetector(),
        new SwiftBicDetector(),
        new PayIdDetector(),
        // Identity
        new EmailDetector(),
        new PhoneAuDetector(),
        new PhoneInternationalDetector(),
        new DateOfBirthDetector(),
        new AddressDetector(),
        new GpsCoordinateDetector(),
        new IpAddressDetector(),
        new HostnameDetector(),
        new UsernameDetector(),
        // Secrets
        new AwsSecretDetector(),
        new AzureSecretDetector(),
        new EntraTokenDetector(),
        new GcpSecretDetector(),
        new JwtDetector(),
        new OAuthTokenDetector(),
        new ApiKeyDetector(),
        new KubernetesSecretDetector(),
        new DockerCredentialDetector(),
        new DatabaseCredentialDetector(),
        new EnvironmentVariableSecretDetector(),
        // Crypto + classification
        new CryptographicMaterialDetector(),
        new SecurityMarkingDetector()
    ];

    public static IFieldNameDetector CreateDefaultFieldNameDetector() => new FieldNameSecretDetector();

    /// <summary>Built-in value detectors followed by the policy's custom detectors, in definition order.</summary>
    public static IReadOnlyList<ISensitiveDetector> CreateValueDetectors(PrivacyPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        IReadOnlyList<ISensitiveDetector> builtIn = CreateDefaultValueDetectors();
        if (policy.CustomDetectors is not { Count: > 0 } custom)
        {
            return builtIn;
        }

        return [.. builtIn, .. custom.Select(definition => new CustomPatternDetector(definition))];
    }

    /// <summary>The built-in field-name detector, extended with the policy's secret field names.</summary>
    public static IFieldNameDetector CreateFieldNameDetector(PrivacyPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        IFieldNameDetector detector = CreateDefaultFieldNameDetector();
        return policy.SecretFieldNames is { Count: > 0 } names
            ? new CompositeFieldNameDetector(detector, names)
            : detector;
    }
}
