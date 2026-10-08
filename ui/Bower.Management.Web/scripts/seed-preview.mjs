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
  { id: "finance-prod-01", machine: "finance-app-01", queue: 3, delivery: "healthy", retention: "Succeeded", deadLettered: 0, ledger: 48211 },
  { id: "claims-prod-03", machine: "claims-api-03", queue: 1294, delivery: "degraded", retention: "Failed", deadLettered: 3, ledger: 902114 },
  { id: "records-prod-04", machine: "records-app-04", queue: 0, delivery: "healthy", retention: "Succeeded", deadLettered: 0, ledger: 7310 },
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
    configurationHash: "sha256:c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
    policyHash: "sha256:4f2a9c1e7b3d58a6c0e2f91b4d7a8c3e5f6b1a2d9c0e7f84b3a5d6c1e2f9a7b8",
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
    configurationHash: "sha256:c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
    policyHash: "sha256:4f2a9c1e7b3d58a6c0e2f91b4d7a8c3e5f6b1a2d9c0e7f84b3a5d6c1e2f9a7b8",
    queueDepth: collector.queue,
    deliveryStatus: collector.delivery,
    deadLettered: collector.deadLettered,
    ledger: { sequence: collector.ledger, hash: `preview-ledger-${collector.ledger}` },
    ...reports(collector),
    jobs: [
      { id: "management-heartbeat", schedule: "* * * * *", lastRunAt: minutesAgo(0.5), lastState: "Succeeded", nextRunAt: minutesAhead(0.5) },
      { id: "queue-maintenance", schedule: "0 3 * * *", lastRunAt: minutesAgo(400), lastState: "Succeeded", nextRunAt: minutesAhead(1040) },
      { id: "queue-retention", schedule: "0 * * * *", lastRunAt: minutesAgo(12), lastState: collector.retention, nextRunAt: minutesAhead(48) }
    ]
  });
}

// Assign the approved policy bundle: finance runs it, claims has drifted.
await call("POST", "/api/collectors/finance-prod-01/desired-policy", {
  policyHash: "sha256:4f2a9c1e7b3d58a6c0e2f91b4d7a8c3e5f6b1a2d9c0e7f84b3a5d6c1e2f9a7b8",
  reason: "Synthetic preview: approved bundle BWR-DEMO-PACK 1.0.0."
});
await call("POST", "/api/collectors/claims-prod-03/desired-policy", {
  policyHash: "sha256:9e81c2d47a5f0b36e1d8c94a7f2b5e60d3a1c8f7e4b29d065c3a8e1f7b42d90c",
  reason: "Synthetic preview: roll out BWR-DEMO-PACK 1.1.0."
});

await call("POST", "/api/collectors/records-prod-04/suspend", {
  reason: "Synthetic preview: host maintenance window."
});
await call("POST", "/api/jobs/collector-staleness/trigger");

console.log(`Seeded ${collectors.length} synthetic preview collectors at ${baseUrl}.`);
