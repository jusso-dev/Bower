//! B1 (council review): the CloudFormation template and the shipped Deny policy keep
//! URL and direct-Invoke ingress separate; each destination gets only its own grant.
//! Read from `deploy/aws` (never copied).

use std::path::{Path, PathBuf};

use serde_yaml_ng::Value;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

/// The template with CloudFormation short-form tags (`!Ref`, `!If`) kept as tagged values.
fn template() -> Value {
    let text =
        std::fs::read_to_string(repo_root().join("deploy/aws/bower-aws-lambda.yaml")).unwrap();
    serde_yaml_ng::from_str(&text).unwrap()
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_sequence()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn ingress_mode_has_no_mixed_option() {
    let template = template();
    assert_eq!(
        strings(&template["Parameters"]["IngressMode"]["AllowedValues"]),
        ["function-url", "invoke"]
    );
    let description = template["Description"].as_str().unwrap();
    assert!(
        description.contains("lambda:InvokeFunction")
            && description.contains("any mapped producer"),
        "the residual same-account risk must be stated: {description}"
    );
    assert!(
        template["Rules"]["InvokeProducerMatchesIngress"].is_mapping(),
        "invoke mode must require InvokeProducer and function-url mode must forbid it"
    );
}

#[test]
fn url_grants_are_limited_to_function_url_calls() {
    let template = template();
    let grants = &template["Resources"]["Fn::ForEach::InvokerGrants"][2];
    let url_invoke = &grants["UrlInvoke&{PrincipalArn}"];
    assert_eq!(url_invoke["Condition"].as_str(), Some("UrlIngress"));
    assert_eq!(
        url_invoke["Properties"]["Action"].as_str(),
        Some("lambda:InvokeFunction")
    );
    assert_eq!(
        url_invoke["Properties"]["InvokedViaFunctionUrl"].as_bool(),
        Some(true)
    );
    let url = &grants["UrlInvokeUrl&{PrincipalArn}"];
    assert_eq!(
        url["Properties"]["FunctionUrlAuthType"].as_str(),
        Some("AWS_IAM")
    );
    let direct = &grants["DirectInvoke&{PrincipalArn}"];
    assert_eq!(direct["Condition"].as_str(), Some("DirectIngress"));
    // Exactly one of the two conditions can hold: they are the two IngressMode values.
    let conditions = format!("{:?}", template["Conditions"]);
    assert!(conditions.contains("invoke") && conditions.contains("function-url"));
    assert!(!format!("{grants:?}").contains("both"));
}

#[test]
fn deny_direct_invoke_policy_blocks_identity_policy_grants() {
    let path = repo_root().join("deploy/aws/policies/bower-lambda-deny-direct-invoke-scp.json");
    let policy: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let statements = policy["Statement"].as_array().unwrap();
    let invoke = statements
        .iter()
        .find(|statement| statement["Action"] == "lambda:InvokeFunction")
        .expect("a Deny on lambda:InvokeFunction");
    assert_eq!(invoke["Effect"], "Deny");
    // Deny unless the call came through the Function URL; an absent key counts as direct.
    assert_eq!(
        invoke["Condition"]["BoolIfExists"]["lambda:InvokedViaFunctionUrl"],
        "false"
    );
    let resources: Vec<&str> = invoke["Resource"]
        .as_array()
        .unwrap()
        .iter()
        .map(|resource| resource.as_str().unwrap())
        .collect();
    assert!(
        resources
            .iter()
            .any(|resource| resource.ends_with(":function:BOWER_URL_FUNCTION_NAME"))
    );
    assert!(
        resources
            .iter()
            .any(|resource| resource.ends_with(":function:BOWER_URL_FUNCTION_NAME:*"))
    );
    let legacy = statements
        .iter()
        .find(|statement| statement["Action"] == "lambda:InvokeAsync")
        .expect("the legacy InvokeAsync API is denied too");
    assert_eq!(legacy["Effect"], "Deny");
}

#[test]
fn separate_invoke_stack_can_reuse_the_channel() {
    // A second stack must not create a second Custom channel for the same account.
    let template = template();
    assert!(template["Parameters"]["ExistingChannelArn"].is_mapping());
    for resource in ["EventDataStore", "Channel"] {
        assert_eq!(
            template["Resources"][resource]["Condition"].as_str(),
            Some("CreateLake"),
            "{resource}"
        );
    }
}

#[test]
fn destination_selects_exactly_one_scoped_write_grant() {
    let template = template();
    let destination = &template["Parameters"]["Destination"];
    assert_eq!(
        strings(&destination["AllowedValues"]),
        ["cloudwatch-logs", "cloudtrail-lake"]
    );
    // No default: updating an existing stack must never switch destination silently.
    assert!(
        destination.get("Default").is_none(),
        "Destination must be required"
    );

    let events = &template["Resources"]["EventLogGroup"];
    assert_eq!(events["Condition"].as_str(), Some("LogsDestination"));
    assert_eq!(events["DeletionPolicy"].as_str(), Some("Retain"));
    // A fixed name would collide with the retained group on recreate or switch-back.
    assert!(
        events["Properties"].get("LogGroupName").is_none(),
        "the retained event log group must have a generated name"
    );

    let statements = format!(
        "{:?}",
        template["Resources"]["ExecutionRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    );
    for (condition, action, resource) in [
        (
            "LakeDestination",
            "cloudtrail-data:PutAuditEvents",
            "Channel.ChannelArn",
        ),
        ("LogsDestination", "logs:PutLogEvents", "EventLogGroup.Arn"),
    ] {
        let grant = statements
            .split(condition)
            .nth(1)
            .unwrap_or_else(|| panic!("{condition} grant missing: {statements}"));
        let grant = &grant[..grant.find("AWS::NoValue").unwrap()];
        assert!(
            grant.contains(action) && grant.contains(resource),
            "{grant}"
        );
    }
    assert!(
        !statements.contains("String(\"*\")"),
        "no wildcard resources"
    );

    let environment = format!(
        "{:?}",
        template["Resources"]["Function"]["Properties"]["Environment"]["Variables"]
    );
    for name in [
        "BOWER_LAMBDA_DESTINATION",
        "BOWER_CLOUDWATCH_LOG_GROUP",
        "BOWER_CLOUDTRAIL_CHANNEL_ARN",
    ] {
        assert!(environment.contains(name), "{name}");
    }
}
