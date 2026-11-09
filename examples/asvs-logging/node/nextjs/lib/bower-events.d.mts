// Types for bower-events.mjs (copied from examples/asvs-logging/node).
export function buildEvent(app: Record<string, unknown>, spec: Record<string, unknown>, options?: { eventId?: string; now?: Date }): Record<string, unknown>;
export function clientIp(remoteAddress: string | undefined, forwardedFor: string | null | undefined, trustedProxies: string[]): string;
export class BowerClient {
  constructor(options?: { endpoint?: string; token?: string; timeoutMs?: number });
  send(event: Record<string, unknown>): Promise<number | null>;
}
