"""Print the contract events and proxy results as JSON lines (see ../contract)."""
import json
import pathlib
import sys
from datetime import datetime

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import bower_events  # noqa: E402

cases = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
now = datetime.fromisoformat(cases["now"].replace("Z", "+00:00"))
for case in cases["cases"]:
    print(json.dumps(bower_events.build_event(cases["app"], case["spec"], event_id=case["eventId"], now=now), sort_keys=True))
for case in cases["proxyCases"]:
    print(json.dumps({"clientIp": bower_events.client_ip(case["remote"], case["forwardedFor"], case["trusted"])}))
