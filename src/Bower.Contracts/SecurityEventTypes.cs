namespace Bower.Contracts;

public static class SecurityEventTypes
{
    public const string AuthenticationFailure = "authentication_failure";
    public const string AuthenticationSuccess = "authentication_success";
    public const string AccountLockout = "account_lockout";
    public const string RoleMembershipChanged = "role_membership_changed";
    public const string SensitiveDataExported = "sensitive_data_exported";
    /// <summary>
    /// Privacy engine detected regulated identifiers, secrets or other sensitive
    /// material in inbound telemetry and applied a control action.
    /// Never carries original secret values — detector ids and actions only.
    /// </summary>
    public const string SensitiveDataDetected = "sensitive_data_detected";
    public const string CollectorStarted = "collector_started";
    public const string CollectorUploadFailed = "collector_upload_failed";
    public const string TelemetryAggregationSummary = "telemetry_aggregation_summary";
}

public static class SecurityEventCategories
{
    public const string Authentication = "authentication";
    public const string Authorisation = "authorisation";
    public const string IdentityManagement = "identity-management";
    public const string AdministrativeActivity = "administrative-activity";
    public const string DataAccess = "data-access";
    public const string ApplicationSecurity = "application-security";
    public const string ApiSecurity = "api-security";
    public const string CollectorHealth = "collector-health";
    /// <summary>Privacy controls, DLP-style findings, data minimisation actions.</summary>
    public const string PrivacyControl = "privacy-control";
}
