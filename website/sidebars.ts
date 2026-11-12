import type { SidebarsConfig } from "@docusaurus/plugin-content-docs";

// Converted from the MkDocs nav in mkdocs.yml: same sections, same order, same page labels.
// tools/docs/tests/test_build_tools.py checks every page in docs/ appears here exactly once.
const sidebars: SidebarsConfig = {
  "startHere": [
    {
      "type": "doc",
      "id": "getting-started/index"
    },
    {
      "type": "doc",
      "id": "getting-started/first-event",
      "label": "Your first verified event"
    },
    {
      "type": "doc",
      "id": "getting-started/concepts",
      "label": "Concepts"
    },
    {
      "type": "doc",
      "id": "getting-started/deployment",
      "label": "Choose a deployment"
    },
    {
      "type": "doc",
      "id": "getting-started/aws-cloudwatch-agent",
      "label": "Quick start: AWS CloudWatch agent"
    },
    {
      "type": "doc",
      "id": "getting-started/azure-monitor-agent",
      "label": "Quick start: Azure Monitor Agent"
    },
    {
      "type": "doc",
      "id": "getting-started/faq",
      "label": "FAQ"
    }
  ],
  "guides": [
    {
      "type": "doc",
      "id": "guides/index"
    },
    {
      "type": "category",
      "label": "Dashboard",
      "collapsed": true,
      "items": [
        {
          "type": "doc",
          "id": "guides/console-tour",
          "label": "Console tour"
        },
        {
          "type": "doc",
          "id": "operations/console-onboarding",
          "label": "Set up Bower"
        },
        {
          "type": "doc",
          "id": "operations/console-home",
          "label": "Home"
        },
        {
          "type": "doc",
          "id": "operations/console-fleet",
          "label": "Fleet"
        },
        {
          "type": "doc",
          "id": "operations/console-sources",
          "label": "Sources"
        },
        {
          "type": "doc",
          "id": "operations/console-privacy-editor",
          "label": "Privacy editor"
        },
        {
          "type": "doc",
          "id": "operations/console-simple-view",
          "label": "Simple view"
        },
        {
          "type": "doc",
          "id": "operations/console-help",
          "label": "Help and checklist"
        }
      ]
    },
    {
      "type": "category",
      "label": "Installation",
      "collapsed": true,
      "items": [
        {
          "type": "doc",
          "id": "deployment/installers",
          "label": "Linux and Windows packages"
        },
        {
          "type": "doc",
          "id": "deployment/console-image",
          "label": "Management console"
        },
        {
          "type": "doc",
          "id": "deployment/container-images",
          "label": "Container images"
        },
        {
          "type": "doc",
          "id": "deployment/docker-sidecar",
          "label": "Docker sidecar"
        },
        {
          "type": "doc",
          "id": "deployment/hosted-collectors",
          "label": "Hosted collectors"
        },
        {
          "type": "doc",
          "id": "deployment/azure-function",
          "label": "Azure Functions"
        },
        {
          "type": "doc",
          "id": "deployment/aws",
          "label": "AWS"
        },
        {
          "type": "doc",
          "id": "deployment/gcp",
          "label": "Google Cloud"
        },
        {
          "type": "doc",
          "id": "deployment/relay",
          "label": "Relay networks"
        },
        {
          "type": "doc",
          "id": "deployment/s3-output",
          "label": "Amazon S3 output"
        },
        {
          "type": "doc",
          "id": "deployment/http-splunk-hec-output",
          "label": "Splunk HEC and NDJSON output"
        },
        {
          "type": "doc",
          "id": "deployment/ama-syslog-output",
          "label": "Syslog output for Azure Monitor Agent"
        },
        {
          "type": "doc",
          "id": "deployment/azure-arc-extension",
          "label": "Azure Arc extension"
        }
      ]
    },
    {
      "type": "category",
      "label": "Connect a source",
      "collapsed": true,
      "items": [
        {
          "type": "doc",
          "id": "deployment/syslog-source",
          "label": "Syslog source"
        },
        {
          "type": "doc",
          "id": "deployment/windows-event-log-source",
          "label": "Windows Event Log"
        },
        {
          "type": "doc",
          "id": "deployment/windows-event-forwarding",
          "label": "Windows Event Forwarding"
        },
        {
          "type": "doc",
          "id": "deployment/file-tail-source",
          "label": "Local files"
        },
        {
          "type": "doc",
          "id": "deployment/ama-companion",
          "label": "Azure Monitor Agent companion"
        },
        {
          "type": "doc",
          "id": "developer-integration/aspnetcore",
          "label": "ASP.NET Core"
        },
        {
          "type": "doc",
          "id": "developer-integration/asvs-logging-frameworks",
          "label": "Web frameworks (ASVS pack)"
        },
        {
          "type": "doc",
          "id": "developer-integration/frameworks/nextjs",
          "label": "Next.js"
        },
        {
          "type": "doc",
          "id": "developer-integration/frameworks/node",
          "label": "Express, Fastify, NestJS"
        },
        {
          "type": "doc",
          "id": "developer-integration/frameworks/python",
          "label": "Django, Flask, FastAPI"
        },
        {
          "type": "doc",
          "id": "developer-integration/frameworks/rails",
          "label": "Rails"
        },
        {
          "type": "doc",
          "id": "developer-integration/frameworks/laravel",
          "label": "Laravel"
        },
        {
          "type": "doc",
          "id": "developer-integration/frameworks/spring-boot",
          "label": "Spring Boot"
        },
        {
          "type": "doc",
          "id": "developer-integration/frameworks/go",
          "label": "Go with log/slog"
        },
        {
          "type": "doc",
          "id": "developer-integration/custom-log-parser",
          "label": "Custom parsers"
        },
        {
          "type": "doc",
          "id": "developer-integration/transform-language",
          "label": "Transform language"
        }
      ]
    },
    {
      "type": "category",
      "label": "Privacy and packs",
      "collapsed": true,
      "items": [
        {
          "type": "doc",
          "id": "privacy/privacy-secret-engine",
          "label": "Privacy engine"
        },
        {
          "type": "doc",
          "id": "privacy/custom-redaction-rules",
          "label": "Custom redaction"
        },
        {
          "type": "doc",
          "id": "privacy/managed-privacy-profiles",
          "label": "Managed profiles"
        },
        {
          "type": "doc",
          "id": "deployment/packs",
          "label": "Signed packs"
        },
        {
          "type": "doc",
          "id": "deployment/database-audit",
          "label": "Database audit"
        }
      ]
    }
  ],
  "productionReadiness": [
    {
      "type": "doc",
      "id": "production-readiness/index"
    },
    {
      "type": "doc",
      "id": "production-readiness/01-syslog-delivery-reliability",
      "label": "1. Syslog delivery"
    },
    {
      "type": "doc",
      "id": "production-readiness/02-replay-safe-detections",
      "label": "2. Replay-safe detections"
    },
    {
      "type": "doc",
      "id": "production-readiness/03-storage-pressure",
      "label": "3. Storage pressure"
    },
    {
      "type": "doc",
      "id": "production-readiness/04-upgrade-backup-recovery",
      "label": "4. Upgrade and recovery"
    },
    {
      "type": "doc",
      "id": "production-readiness/05-credential-rotation-and-security-failures",
      "label": "5. Credentials and security failures"
    },
    {
      "type": "doc",
      "id": "production-readiness/06-monitoring-and-runbooks",
      "label": "6. Monitoring and runbooks"
    },
    {
      "type": "doc",
      "id": "production-readiness/07-soak-and-release-validation",
      "label": "7. Soak and release validation"
    }
  ],
  "operations": [
    {
      "type": "doc",
      "id": "operations/index"
    },
    {
      "type": "doc",
      "id": "operations/tap-and-top",
      "label": "Live pipeline inspection"
    },
    {
      "type": "doc",
      "id": "operations/evidence-bundles",
      "label": "Prove delivery"
    },
    {
      "type": "doc",
      "id": "operations/doctor-and-dcr",
      "label": "Diagnose DCR issues"
    },
    {
      "type": "doc",
      "id": "operations/fleet-and-queue-integrity",
      "label": "Queue and fleet integrity"
    },
    {
      "type": "doc",
      "id": "operations/queue-v5-durability",
      "label": "Queue durability"
    },
    {
      "type": "doc",
      "id": "operations/release-versioning",
      "label": "Release versioning"
    },
    {
      "type": "doc",
      "id": "operations/lab-and-stress-testing",
      "label": "AWS lab and stress testing"
    },
    {
      "type": "doc",
      "id": "operations/aws-emulator-testing",
      "label": "AWS Emulator end-to-end test"
    },
    {
      "type": "doc",
      "id": "operations/event-identity-conflicts",
      "label": "Event identity conflicts"
    },
    {
      "type": "doc",
      "id": "operations/suppression-archive-and-source-silence",
      "label": "Source silence"
    },
    {
      "type": "doc",
      "id": "operations/azure-sdk-recovery",
      "label": "Azure SDK recovery"
    },
    {
      "type": "doc",
      "id": "operations/background-jobs",
      "label": "Background jobs"
    },
    {
      "type": "doc",
      "id": "operations/powershell",
      "label": "PowerShell"
    }
  ],
  "security": [
    {
      "type": "doc",
      "id": "security/index"
    },
    {
      "type": "doc",
      "id": "security/threat-model",
      "label": "Threat model"
    },
    {
      "type": "doc",
      "id": "security/management-identity-and-rbac",
      "label": "Roles and identity"
    },
    {
      "type": "doc",
      "id": "security/producer-scopes",
      "label": "Producer scopes"
    },
    {
      "type": "doc",
      "id": "security/ism-alignment",
      "label": "ISM alignment"
    },
    {
      "type": "doc",
      "id": "security/verified-standards",
      "label": "Verified ASVS and ISM IDs"
    },
    {
      "type": "doc",
      "id": "security/default-event-catalogue",
      "label": "Event catalogue"
    },
    {
      "type": "doc",
      "id": "security/asvs-logging-pack",
      "label": "ASVS logging pack"
    },
    {
      "type": "doc",
      "id": "security/pack-runtime-catalogue",
      "label": "Pack catalogue"
    },
    {
      "type": "category",
      "label": "Engineering reviews",
      "collapsed": true,
      "items": [
        {
          "type": "doc",
          "id": "security/adversarial-remediation-2026-10-23",
          "label": "Adversarial remediation"
        },
        {
          "type": "doc",
          "id": "operations/policy-population-2026-10-23",
          "label": "Policy population review"
        }
      ]
    }
  ],
  "reference": [
    {
      "type": "doc",
      "id": "reference/index"
    },
    {
      "type": "doc",
      "id": "reference/cli",
      "label": "bower CLI"
    },
    {
      "type": "doc",
      "id": "reference/sentinel-table",
      "label": "BowerSecurity_CL columns"
    },
    {
      "type": "doc",
      "id": "architecture/overview",
      "label": "Architecture"
    },
    {
      "type": "doc",
      "id": "architecture/collector-enrolment",
      "label": "Collector enrolment"
    },
    {
      "type": "doc",
      "id": "architecture/heartbeat-v2",
      "label": "Heartbeats"
    },
    {
      "type": "doc",
      "id": "architecture/transform-language",
      "label": "Transform design"
    },
    {
      "type": "doc",
      "id": "architecture/windows-event-forwarding-decision",
      "label": "Windows Event Forwarding decision"
    },
    {
      "type": "doc",
      "id": "architecture/durable-azure-ingest-decision",
      "label": "Durable Azure ingest (proposed)"
    },
    {
      "type": "doc",
      "id": "deployment/logs-ingestion-api",
      "label": "Azure ingestion API"
    },
    {
      "type": "doc",
      "id": "deployment/entra-ingestion-plan",
      "label": "Entra ingestion plan"
    },
    {
      "type": "doc",
      "id": "deployment/cloud-permission-context",
      "label": "Cloud permissions"
    },
    {
      "type": "doc",
      "id": "architecture/ci",
      "label": "Continuous integration"
    },
    {
      "type": "doc",
      "id": "architecture/dependencies",
      "label": "Dependencies"
    },
    {
      "type": "doc",
      "id": "architecture/documentation-site",
      "label": "Site architecture"
    },
    {
      "type": "doc",
      "id": "reference/accessibility",
      "label": "Accessibility"
    }
  ]
};

export default sidebars;
