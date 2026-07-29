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
}
