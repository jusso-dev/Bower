package example.bower;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Pattern;

/**
 * Bower security events for Java services (Spring Boot). JDK only. Builds Bower envelope 1.0.0
 * events, sanitises them before they leave the process and posts them to a Bower collector.
 * The collector redacts again; this is defence in depth.
 */
public final class BowerEvents {
    public static final String SCHEMA_VERSION = "1.0.0";
    private static final Pattern CONTROL = Pattern.compile("[\\x00-\\x1f\\x7f\\u2028\\u2029]+");
    private static final Pattern NON_ALNUM = Pattern.compile("[^a-z0-9]");
    private static final List<String> SECRET_FRAGMENTS = List.of("password", "passwd", "passphrase", "secret", "token",
            "apikey", "cookie", "authorization", "credential", "privatekey", "signature");
    private static final Set<String> SECRET_NAMES = Set.of("body", "rawbody", "requestbody", "responsebody", "headers",
            "payload", "otp", "otpcode", "totp", "mfacode", "verificationcode", "recoverycode", "backupcode", "stacktrace",
            "exceptionmessage", "statement", "querytext", "sqltext", "querystring", "rawquery");
    private static final Map<String, Integer> LIMITS = Map.of("eventOutcomeReason", 1024, "path", 2048);
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    private BowerEvents() {
    }

    public static boolean isSecret(String name) {
        String normal = NON_ALNUM.matcher(name.toLowerCase(java.util.Locale.ROOT)).replaceAll("");
        return SECRET_NAMES.contains(normal) || SECRET_FRAGMENTS.stream().anyMatch(normal::contains);
    }

    private static String truncate(String text, int limit) {
        int[] points = text.codePoints().toArray();
        return points.length <= limit ? text : new String(points, 0, limit);
    }

    @SuppressWarnings("unchecked")
    static Object clean(Object value, String key) {
        if (value instanceof String text) {
            return truncate(CONTROL.matcher(text).replaceAll(" "), LIMITS.getOrDefault(key, 256));
        }
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String name = String.valueOf(entry.getKey());
                if (isSecret(name) || entry.getValue() == null) {
                    continue;
                }
                Object cleaned = clean(entry.getValue(), name);
                if (cleaned instanceof Map<?, ?> m && m.isEmpty()) {
                    continue;
                }
                out.put(truncate(CONTROL.matcher(name).replaceAll(" "), 128), cleaned);
            }
            return out;
        }
        if (value instanceof List<?> list) {
            List<Object> out = new ArrayList<>();
            for (Object item : list.subList(0, Math.min(64, list.size()))) {
                out.add(clean(item, ""));
            }
            return out;
        }
        return value;
    }

    /** UTC, millisecond precision, Z suffix (ASVS 5.0 V16.2.2). */
    public static String formatTime(Instant instant) {
        return TIME.format(instant);
    }

    private static Map<String, Object> map(Object value) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (value instanceof Map<?, ?> m) {
            m.forEach((k, v) -> out.put(String.valueOf(k), v));
        }
        return out;
    }

    private static String str(Map<String, Object> spec, String key) {
        Object value = spec.get(key);
        return value == null ? null : value.toString();
    }

    /**
     * Build a sanitised envelope. spec keys: eventType, eventCategory, eventAction, eventResult,
     * eventSeverity, reason, actor, target, sourceIp, userAgent, route, tenantId, request,
     * labels, attributes, change.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> build(Map<String, Object> app, Map<String, Object> spec, String eventId, Instant now) {
        Map<String, Object> application = new LinkedHashMap<>();
        for (String key : List.of("name", "environment", "version", "instance")) {
            if (app.get(key) != null) {
                application.put(key, app.get(key));
            }
        }
        if (str(spec, "tenantId") != null) {
            application.put("tenantId", str(spec, "tenantId"));
        }
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("schemaVersion", SCHEMA_VERSION);
        event.put("eventId", eventId != null ? eventId : UUID.randomUUID().toString());
        event.put("timeGenerated", formatTime(now != null ? now : Instant.now()));
        event.put("eventCategory", str(spec, "eventCategory"));
        event.put("eventType", str(spec, "eventType"));
        event.put("eventAction", str(spec, "eventAction"));
        event.put("eventResult", str(spec, "eventResult"));
        event.put("eventSeverity", Objects.requireNonNullElse(str(spec, "eventSeverity"), "informational"));
        event.put("application", application);
        if (str(spec, "reason") != null) {
            event.put("eventOutcomeReason", str(spec, "reason"));
        }
        for (String part : List.of("actor", "target")) {
            Map<String, Object> value = map(spec.get(part));
            if (!value.isEmpty()) {
                event.put(part, value);
            }
        }
        if (str(spec, "sourceIp") != null) {
            event.put("source", Map.of("ipAddress", str(spec, "sourceIp")));
        }
        Map<String, Object> request = map(spec.get("request"));
        if (request.get("path") instanceof String path) {
            request.put("path", path.split("[?#]", 2)[0]);
        }
        if (!request.isEmpty()) {
            event.put("request", request);
        }
        Map<String, Object> labels = new LinkedHashMap<>();
        map(spec.get("labels")).forEach((k, v) -> labels.put(k, String.valueOf(v)));
        if (str(spec, "userAgent") != null) {
            labels.put("userAgent", str(spec, "userAgent"));
        }
        if (str(spec, "route") != null) {
            labels.put("route", str(spec, "route"));
        }
        if (!labels.isEmpty()) {
            event.put("labels", labels);
        }
        Map<String, Object> attributes = map(spec.get("attributes"));
        if (!attributes.isEmpty()) {
            event.put("attributes", attributes);
        }
        Map<String, Object> change = map(spec.get("change"));
        // Before and after values of settings and credentials never leave the process.
        if (!change.isEmpty() && !"role_membership_changed".equals(str(spec, "eventType"))) {
            change = change.containsKey("field") ? new LinkedHashMap<>(Map.of("field", change.get("field"))) : new LinkedHashMap<>();
        }
        if (!change.isEmpty()) {
            event.put("change", change);
        }
        return (Map<String, Object>) clean(event, "");
    }

    private static InetAddress parse(String address) {
        // Literal addresses only: never resolve names.
        // Dotted-quad IPv4, or a value with a colon (Java treats it as an IPv6 literal and never
        // looks it up). Hex-only names such as "cafe" would otherwise go to DNS.
        if (address == null || address.isEmpty()
                || !(address.matches("\\d{1,3}(\\.\\d{1,3}){3}")
                    || (address.contains(":") && address.matches("[0-9A-Fa-f:.]+")))) {
            return null;
        }
        try {
            return InetAddress.getByName(address);
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean inCidr(InetAddress ip, String cidr) {
        String[] parts = cidr.split("/", 2);
        InetAddress network = parse(parts[0]);
        if (network == null || network.getAddress().length != ip.getAddress().length) {
            return false;
        }
        int width = ip.getAddress().length * 8;
        int bits = parts.length == 2 ? Integer.parseInt(parts[1]) : width;
        BigInteger mask = BigInteger.ONE.shiftLeft(width).subtract(BigInteger.ONE).shiftRight(bits).not();
        return new BigInteger(1, ip.getAddress()).and(mask).equals(new BigInteger(1, network.getAddress()).and(mask));
    }

    /**
     * Original client address (ASVS 5.0 V15.3.4, V4.1.3). X-Forwarded-For is read only when the
     * direct peer is a trusted proxy, right to left, skipping trusted hops.
     */
    public static String clientIp(String remote, String forwardedFor, List<String> trustedProxies) {
        java.util.function.Predicate<String> trusted = address -> {
            InetAddress ip = parse(address);
            return ip != null && trustedProxies.stream().anyMatch(cidr -> inCidr(ip, cidr));
        };
        if (forwardedFor == null || forwardedFor.isEmpty() || !trusted.test(remote)) {
            return remote;
        }
        List<String> hops = new ArrayList<>();
        for (String hop : forwardedFor.split(",")) {
            if (!hop.isBlank()) {
                hops.add(hop.strip());
            }
        }
        for (int i = hops.size() - 1; i >= 0; i--) {
            if (!trusted.test(hops.get(i))) {
                InetAddress ip = parse(hops.get(i));
                return ip == null ? remote : ip.getHostAddress();
            }
        }
        return hops.isEmpty() ? remote : hops.get(0);
    }

    /** Minimal JSON writer for the envelope's types (maps, lists, strings, numbers, booleans). */
    public static String toJson(Object value) {
        StringBuilder out = new StringBuilder();
        write(out, value);
        return out.toString();
    }

    private static void write(StringBuilder out, Object value) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String s) {
            out.append('"');
            for (char c : s.toCharArray()) {
                switch (c) {
                    case '"' -> out.append("\\\"");
                    case '\\' -> out.append("\\\\");
                    default -> {
                        if (c < 0x20 || c > 0x7e) {
                            out.append(String.format("\\u%04x", (int) c));
                        } else {
                            out.append(c);
                        }
                    }
                }
            }
            out.append('"');
        } else if (value instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                write(out, String.valueOf(entry.getKey()));
                out.append(':');
                write(out, entry.getValue());
            }
            out.append('}');
        } else if (value instanceof List<?> list) {
            out.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) {
                    out.append(',');
                }
                write(out, list.get(i));
            }
            out.append(']');
        } else {
            out.append(value);
        }
    }

    /** Posts events to a Bower collector. Never throws into the request path. */
    public static final class Client {
        private final URI uri;
        private final String token;
        private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();

        public Client(String endpoint, String token) {
            String base = endpoint != null ? endpoint : "http://127.0.0.1:4319";
            this.uri = URI.create(base.replaceAll("/+$", "") + "/v1/events");
            this.token = token;
        }

        public static Client fromEnvironment() {
            return new Client(System.getenv("BOWER_COLLECTOR_URL"), System.getenv("BOWER_INGEST_TOKEN"));
        }

        public CompletableFuture<Integer> send(Map<String, Object> event) {
            HttpRequest.Builder request = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(2))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(toJson(event)));
            if (token != null && !token.isEmpty()) {
                request.header("Authorization", "Bearer " + token);
            }
            return http.sendAsync(request.build(), HttpResponse.BodyHandlers.discarding())
                    .thenApply(HttpResponse::statusCode)
                    .exceptionally(error -> null);
        }
    }
}
