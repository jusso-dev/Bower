using Bower.Redaction.Privacy;

namespace Bower.Management.Api;

/// <summary>
/// Plain-English names for detector types on the home view. Secrets share one group, as do a
/// tenant's own custom detectors; an unknown type is "other sensitive details". Names only:
/// counts are by type, never values.
/// </summary>
public static class RedactionLabels
{
    public const string Secrets = "secrets";
    public const string Custom = "custom";
    public const string Phone = "phone";
    public const string Other = "other";

    private static readonly Dictionary<string, string> Labels = new(StringComparer.Ordinal)
    {
        [DetectorIds.Tfn] = "Tax file numbers",
        [DetectorIds.Crn] = "Centrelink reference numbers",
        [DetectorIds.Medicare] = "Medicare card numbers",
        [DetectorIds.Ihi] = "Healthcare identifiers",
        [DetectorIds.Passport] = "Passport numbers",
        [DetectorIds.DriverLicence] = "Driver licence numbers",
        [DetectorIds.Abn] = "Australian business numbers",
        [DetectorIds.Acn] = "Australian company numbers",
        [DetectorIds.Dva] = "Veterans' file numbers",
        [DetectorIds.CreditCard] = "Credit card numbers",
        [DetectorIds.BsbAccount] = "Bank account numbers",
        [DetectorIds.Iban] = "International bank account numbers",
        [DetectorIds.SwiftBic] = "Bank SWIFT codes",
        [DetectorIds.PayId] = "PayIDs",
        [DetectorIds.Email] = "Email addresses",
        [Phone] = "Phone numbers",
        [DetectorIds.DateOfBirth] = "Dates of birth",
        [DetectorIds.Address] = "Street addresses",
        [DetectorIds.Gps] = "Map locations",
        [DetectorIds.IpAddress] = "Network addresses",
        [DetectorIds.Hostname] = "Computer names",
        [DetectorIds.Username] = "Usernames",
        [Secrets] = "Passwords, keys and access tokens",
        [DetectorIds.SecurityMarking] = "Security classification markings",
        [DetectorIds.FieldRule] = "Fields your privacy profile removes",
        [DetectorIds.FieldLength] = "Very long fields shortened",
        [Custom] = "Matches for your own privacy rules",
        [Other] = "Other sensitive details"
    };

    /// <summary>The home-view group a reported type counts towards.</summary>
    public static string Group(string type)
    {
        if (type.StartsWith("secret.", StringComparison.Ordinal)
            || type is DetectorIds.FieldNameSecret or DetectorIds.CryptoMaterial)
        {
            return Secrets;
        }

        if (type is DetectorIds.PhoneAu or DetectorIds.PhoneInternational)
        {
            return Phone;
        }

        if (type.StartsWith("custom.", StringComparison.Ordinal))
        {
            return Custom;
        }

        return Labels.ContainsKey(type) && type is not (Secrets or Custom or Phone) ? type : Other;
    }

    public static string Label(string group) => Labels.GetValueOrDefault(group, Labels[Other]);
}
