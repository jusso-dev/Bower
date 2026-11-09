// Print the contract events and proxy results as JSON lines (see ../contract).
import { readFileSync } from 'node:fs';
import { buildEvent, clientIp } from './bower-events.mjs';

const sortKeys = (value) => Array.isArray(value) ? value.map(sortKeys)
  : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map((k) => [k, sortKeys(value[k])])) : value;
const pyJson = (value) => JSON.stringify(sortKeys(value)).replace(/":/g, '": ').replace(/,"/g, ', "');

const cases = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const now = new Date(cases.now);
for (const c of cases.cases) console.log(pyJson(buildEvent(cases.app, c.spec, { eventId: c.eventId, now })));
for (const c of cases.proxyCases) console.log(pyJson({ clientIp: clientIp(c.remote, c.forwardedFor, c.trusted) }));
