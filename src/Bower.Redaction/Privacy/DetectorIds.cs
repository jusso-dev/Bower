namespace Bower.Redaction.Privacy;

/// <summary>Stable detector identifiers used for policy overrides and metadata.</summary>
public static class DetectorIds
{
    public const string FieldNameSecret = "field-name-secret";

    // Australian regulated identifiers
    public const string Tfn = "au.tfn";
    public const string Crn = "au.crn";
    public const string Medicare = "au.medicare";
    public const string Ihi = "au.ihi";
    public const string Passport = "au.passport";
    public const string DriverLicence = "au.driver-licence";
    public const string Abn = "au.abn";
    public const string Acn = "au.acn";
    public const string Dva = "au.dva";

    // Financial
    public const string CreditCard = "fin.credit-card";
    public const string BsbAccount = "fin.bsb-account";
    public const string Iban = "fin.iban";
    public const string SwiftBic = "fin.swift-bic";
    public const string PayId = "fin.payid";

    // Identity / personal
    public const string Email = "id.email";
    public const string PhoneAu = "id.phone.au";
    public const string PhoneInternational = "id.phone.intl";
    public const string DateOfBirth = "id.dob";
    public const string Address = "id.address";
    public const string Gps = "id.gps";
    public const string IpAddress = "id.ip";
    public const string Hostname = "id.hostname";
    public const string Username = "id.username";

    // Cloud / auth secrets
    public const string Aws = "secret.aws";
    public const string Azure = "secret.azure";
    public const string Entra = "secret.entra";
    public const string Gcp = "secret.gcp";
    public const string Jwt = "secret.jwt";
    public const string OAuth = "secret.oauth";
    public const string ApiKey = "secret.api-key";
    public const string Kubernetes = "secret.kubernetes";
    public const string Docker = "secret.docker";
    public const string Database = "secret.database";
    public const string EnvVar = "secret.env-var";

    // Crypto material
    public const string CryptoMaterial = "crypto.material";

    // Classification markings
    public const string SecurityMarking = "class.security-marking";
}

public static class DetectorCategories
{
    public const string FieldName = "field-name";
    public const string Australian = "australian";
    public const string Financial = "financial";
    public const string Identity = "identity";
    public const string Secrets = "secrets";
    public const string Crypto = "crypto";
    public const string Classification = "classification";
}
