//! Stable detector identifiers (`DetectorIds`) and categories (`DetectorCategories`).

pub mod detector_ids {
    pub const FIELD_NAME_SECRET: &str = "field-name-secret";
    /// A configured field rule (for example HMAC pseudonymisation) was applied.
    pub const FIELD_RULE: &str = "field-rule";
    /// A value exceeded the maximum field length and was truncated.
    pub const FIELD_LENGTH: &str = "limit.field-length";

    // Australian regulated identifiers
    pub const TFN: &str = "au.tfn";
    pub const CRN: &str = "au.crn";
    pub const MEDICARE: &str = "au.medicare";
    pub const IHI: &str = "au.ihi";
    pub const PASSPORT: &str = "au.passport";
    pub const DRIVER_LICENCE: &str = "au.driver-licence";
    pub const ABN: &str = "au.abn";
    pub const ACN: &str = "au.acn";
    pub const DVA: &str = "au.dva";

    // Financial
    pub const CREDIT_CARD: &str = "fin.credit-card";
    pub const BSB_ACCOUNT: &str = "fin.bsb-account";
    pub const IBAN: &str = "fin.iban";
    pub const SWIFT_BIC: &str = "fin.swift-bic";
    pub const PAY_ID: &str = "fin.payid";

    // Identity / personal
    pub const EMAIL: &str = "id.email";
    pub const PHONE_AU: &str = "id.phone.au";
    pub const PHONE_INTERNATIONAL: &str = "id.phone.intl";
    pub const DATE_OF_BIRTH: &str = "id.dob";
    pub const ADDRESS: &str = "id.address";
    pub const GPS: &str = "id.gps";
    pub const IP_ADDRESS: &str = "id.ip";
    pub const HOSTNAME: &str = "id.hostname";
    pub const USERNAME: &str = "id.username";

    // Cloud / auth secrets
    pub const AWS: &str = "secret.aws";
    pub const AZURE: &str = "secret.azure";
    pub const ENTRA: &str = "secret.entra";
    pub const GCP: &str = "secret.gcp";
    pub const JWT: &str = "secret.jwt";
    pub const OAUTH: &str = "secret.oauth";
    pub const API_KEY: &str = "secret.api-key";
    pub const KUBERNETES: &str = "secret.kubernetes";
    pub const DOCKER: &str = "secret.docker";
    pub const DATABASE: &str = "secret.database";
    pub const ENV_VAR: &str = "secret.env-var";

    // Crypto material
    pub const CRYPTO_MATERIAL: &str = "crypto.material";

    // Classification markings
    pub const SECURITY_MARKING: &str = "class.security-marking";

    /// Every stable detector id, in declaration order, for validating configuration.
    pub const ALL: &[&str] = &[
        FIELD_NAME_SECRET,
        FIELD_RULE,
        FIELD_LENGTH,
        TFN,
        CRN,
        MEDICARE,
        IHI,
        PASSPORT,
        DRIVER_LICENCE,
        ABN,
        ACN,
        DVA,
        CREDIT_CARD,
        BSB_ACCOUNT,
        IBAN,
        SWIFT_BIC,
        PAY_ID,
        EMAIL,
        PHONE_AU,
        PHONE_INTERNATIONAL,
        DATE_OF_BIRTH,
        ADDRESS,
        GPS,
        IP_ADDRESS,
        HOSTNAME,
        USERNAME,
        AWS,
        AZURE,
        ENTRA,
        GCP,
        JWT,
        OAUTH,
        API_KEY,
        KUBERNETES,
        DOCKER,
        DATABASE,
        ENV_VAR,
        CRYPTO_MATERIAL,
        SECURITY_MARKING,
    ];
}

pub mod detector_categories {
    pub const FIELD_NAME: &str = "field-name";
    pub const AUSTRALIAN: &str = "australian";
    pub const FINANCIAL: &str = "financial";
    pub const IDENTITY: &str = "identity";
    pub const SECRETS: &str = "secrets";
    pub const CRYPTO: &str = "crypto";
    pub const CLASSIFICATION: &str = "classification";
    /// Custom detectors defined in a privacy profile.
    pub const CUSTOM: &str = "custom";
}
