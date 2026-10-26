// Test-only stand-in for a Bower collector's event intake, for the setup wizard journey.
// Loopback only. Accepts a canary posted with the expected bearer token and nothing else; it
// never forwards anything, so a run through it can only ever be "simulated".
import { createServer } from "node:http";

const port = Number(process.env.BOWER_E2E_COLLECTOR_PORT ?? 4399);
const token = process.env.BOWER_E2E_CANARY_TOKEN ?? "e2e-canary-token";

function reply(response, status, body) {
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(JSON.stringify(body));
}

createServer((request, response) => {
  if (request.method === "GET" && request.url === "/health") {
    reply(response, 200, { status: "healthy" });
    return;
  }
  if (request.method !== "POST" || request.url !== "/v1/events") {
    reply(response, 404, { error: "not-found" });
    return;
  }
  if (request.headers.authorization !== `Bearer ${token}`) {
    reply(response, 401, { error: "unauthorized" });
    return;
  }
  let size = 0;
  request.on("data", (chunk) => {
    size += chunk.length;
    if (size > 1024 * 1024) {
      request.destroy();
    }
  });
  request.on("end", () => reply(response, 202, { decision: "accept" }));
}).listen(port, "127.0.0.1");
