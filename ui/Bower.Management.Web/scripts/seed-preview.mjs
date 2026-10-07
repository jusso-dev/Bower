// Seeds a development-auth management API with synthetic, clearly labelled preview data
// for screenshots and end-to-end tests. Refuses to run unless the API reports
// development authentication, so it can never write demo rows into a real tenant.
const baseUrl = (process.argv[2] ?? process.env.BOWER_UI_BASE_URL ?? "http://127.0.0.1:4320").replace(/\/$/, "");

async function call(method, path, body) {
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined
  });
  if (!response.ok && response.status !== 409) {
    throw new Error(`${method} ${path} failed with HTTP ${response.status}`);
  }
  const text = await response.text();
  return text ? JSON.parse(text) : undefined;
}

const access = await call("GET", "/api/access/me");
if (!access?.developmentAuthentication) {
  throw new Error("Refusing to seed: the target API is not in development authentication mode.");
}

const now = Date.now();
const minutesAgo = (minutes) => new Date(now - minutes * 60_000).toISOString();
const minutesAhead = (minutes) => new Date(now + minutes * 60_000).toISOString();

const collectors = [
  { id: "finance-prod-01", machine: "finance-app-01", queue: 3, delivery: "healthy", retention: "Succeeded" },
  { id: "claims-prod-03", machine: "claims-api-03", queue: 1294, delivery: "degraded", retention: "Failed" },
  { id: "records-prod-04", machine: "records-app-04", queue: 0, delivery: "healthy", retention: "Succeeded" },
  { id: "hr-legacy-02", machine: "hr-app-02" }
];

function reports(collector) {
  return {
    sources: [
      { id: "local-http", type: "local-http", status: "healthy", lagSeconds: null, lastEventAt: minutesAgo(1) }
    ],
    outputs: [
      {
        id: "azure-logs-ingestion",
        type: "azure-logs-ingestion",
        status: collector.delivery ?? "unknown",
        lastAcknowledgedAt: minutesAgo(2),
        lastErrorCode: collector.delivery === "degraded" ? "azure-http-429" : null
      }
    ]
  };
}

for (const collector of collectors) {
  await call("POST", "/api/collectors/register", {
    collectorId: collector.id,
    machineName: collector.machine,
    environment: "production",
    version: "0.1.0",
    configurationHash: "sha256:preview-configuration",
    policyHash: "sha256:preview-policy",
    ...reports(collector)
  });
}

const approvals = [
  ["finance-prod-01", "Synthetic preview: matched approved server inventory BWR-DEMO-001."],
  ["claims-prod-03", "Synthetic preview: approved workload identity BWR-DEMO-002."],
  ["records-prod-04", "Synthetic preview: approved collector BWR-DEMO-003."]
];
for (const [id, reason] of approvals) {
  await call("POST", `/api/approvals/${id}/approve`, { reason });
}

for (const collector of collectors.filter((item) => item.delivery)) {
  await call("POST", `/api/collectors/${collector.id}/heartbeat`, {
    version: "0.1.0",
    configurationHash: "sha256:preview-configuration",
    policyHash: "sha256:preview-policy",
    queueDepth: collector.queue,
    deliveryStatus: collector.delivery,
    ...reports(collector),
    jobs: [
      { id: "management-heartbeat", schedule: "* * * * *", lastRunAt: minutesAgo(0.5), lastState: "Succeeded", nextRunAt: minutesAhead(0.5) },
      { id: "queue-maintenance", schedule: "0 3 * * *", lastRunAt: minutesAgo(400), lastState: "Succeeded", nextRunAt: minutesAhead(1040) },
      { id: "queue-retention", schedule: "0 * * * *", lastRunAt: minutesAgo(12), lastState: collector.retention, nextRunAt: minutesAhead(48) }
    ]
  });
}

await call("POST", "/api/collectors/records-prod-04/suspend", {
  reason: "Synthetic preview: host maintenance window."
});
await call("POST", "/api/jobs/collector-staleness/trigger");

console.log(`Seeded ${collectors.length} synthetic preview collectors at ${baseUrl}.`);
