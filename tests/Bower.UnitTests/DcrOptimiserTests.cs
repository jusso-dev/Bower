using Bower.Dcr;

namespace Bower.UnitTests;

public sealed class DcrOptimiserTests
{
    [Fact]
    public void Assess_FlagsBroadSecurityAndMissingSysmon()
    {
        const string json =
            """
            {
              "id": "dcr-1",
              "name": "servers",
              "workspaceId": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law",
              "dataSources": [
                {
                  "name": "windows-security",
                  "kind": "windowsEventLogs",
                  "streams": ["Microsoft-WindowsEvent"],
                  "xPathQueries": ["Security!*"]
                }
              ],
              "destinations": [{ "name": "law" }]
            }
            """;

        DcrDocument document = DcrDocumentParser.Parse(json);
        DcrAssessmentReport report = DcrOptimiser.Assess(document, currentMonthlyIngestionGb: 100);

        Assert.Contains(report.Recommendations, item => item.Code == "broad-security-events");
        Assert.Contains(report.Recommendations, item => item.Code == "missing-sysmon");
        Assert.True(report.EstimatedMonthlySavingsGb is > 0);
        Assert.True(report.HealthScore < 100);
        Assert.Contains("DCR Assessment", DcrOptimiser.ExportMarkdown(report));
    }

    [Fact]
    public void Assess_HealthyDcr_ScoresHigh()
    {
        DcrDocument document = new(
            "dcr-good",
            "good",
            "law",
            [
                new DcrDataSource(
                    "security",
                    "windowsEventLogs",
                    ["Microsoft-WindowsEvent"],
                    ["Security!*[System[(EventID=4624 or EventID=4625 or EventID=4688)]]"],
                    true),
                new DcrDataSource(
                    "sysmon",
                    "windowsEventLogs",
                    ["Microsoft-WindowsEvent"],
                    ["Microsoft-Windows-Sysmon/Operational!*[System[(EventID=1 or EventID=3 or EventID=11)]]"],
                    true),
                new DcrDataSource(
                    "defender",
                    "windowsEventLogs",
                    ["Microsoft-Windows-Windows Defender/Operational"],
                    [],
                    true),
                new DcrDataSource(
                    "iis",
                    "iisLogs",
                    ["Microsoft-IIS"],
                    [],
                    true)
            ],
            ["law"]);

        DcrAssessmentReport report = DcrOptimiser.Assess(document);

        Assert.True(report.CoverageScore >= 90);
        Assert.DoesNotContain(report.Recommendations, item => item.Code == "missing-sysmon");
    }
}
