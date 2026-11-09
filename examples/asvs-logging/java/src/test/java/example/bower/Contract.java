package example.bower;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Prints the contract events and proxy results as JSON lines (see ../contract). */
public final class Contract {
    @SuppressWarnings("unchecked")
    private static Object sortKeys(Object value) {
        if (value instanceof Map<?, ?> map) {
            TreeMap<String, Object> out = new TreeMap<>();
            map.forEach((k, v) -> out.put(String.valueOf(k), sortKeys(v)));
            return out;
        }
        if (value instanceof List<?> list) {
            return list.stream().map(Contract::sortKeys).toList();
        }
        return value;
    }

    /** Python json.dumps(sort_keys=True) separators. */
    private static String pyJson(Object value) {
        return BowerEvents.toJson(sortKeys(value)).replace("\":", "\": ").replace(",\"", ", \"");
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        Map<String, Object> cases = new ObjectMapper().readValue(Files.readString(Path.of(args[0])), Map.class);
        Map<String, Object> app = (Map<String, Object>) cases.get("app");
        Instant now = Instant.parse((String) cases.get("now"));
        for (Map<String, Object> c : (List<Map<String, Object>>) cases.get("cases")) {
            System.out.println(pyJson(BowerEvents.build(app, (Map<String, Object>) c.get("spec"), (String) c.get("eventId"), now)));
        }
        for (Map<String, Object> c : (List<Map<String, Object>>) cases.get("proxyCases")) {
            String ip = BowerEvents.clientIp((String) c.get("remote"), (String) c.get("forwardedFor"), (List<String>) c.get("trusted"));
            System.out.println(pyJson(Map.of("clientIp", ip)));
        }
    }
}
