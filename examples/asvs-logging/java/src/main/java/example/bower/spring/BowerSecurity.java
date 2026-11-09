package example.bower.spring;

import example.bower.BowerEvents;
import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.HandlerMapping;

/** Builds and sends Bower events with the current request's context. Never throws. */
@Component
public class BowerSecurity {
    private final BowerEvents.Client client = BowerEvents.Client.fromEnvironment();
    private final Map<String, Object> app;

    public BowerSecurity(@Value("${spring.application.name:spring-example}") String name,
                         @Value("${app.environment:development}") String environment) {
        this.app = Map.of("name", name, "environment", environment, "version", "1.0.0");
    }

    public void emit(Map<String, Object> spec) {
        HttpServletRequest request = RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs
                ? attrs.getRequest() : null;
        Map<String, Object> full = new HashMap<>(spec);
        if (request != null) {
            Object pattern = request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
            full.putIfAbsent("sourceIp", request.getAttribute(BowerRequestFilter.CLIENT_IP));
            full.putIfAbsent("userAgent", request.getHeader("User-Agent"));
            full.putIfAbsent("route", pattern != null ? pattern : request.getRequestURI());
            full.putIfAbsent("request", Map.of(
                    "correlationId", String.valueOf(request.getAttribute(BowerRequestFilter.REQUEST_ID)),
                    "method", request.getMethod(),
                    "path", request.getRequestURI()));
        }
        client.send(BowerEvents.build(app, full, null, null));
    }
}
