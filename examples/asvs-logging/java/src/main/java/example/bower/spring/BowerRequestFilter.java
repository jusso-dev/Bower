package example.bower.spring;

import example.bower.BowerEvents;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Request ID (honours a W3C traceparent, also put in the logging MDC) and trusted-proxy client
 * IP. Keep server.forward-headers-strategy=none: this filter applies the trusted list itself.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class BowerRequestFilter extends OncePerRequestFilter {
    public static final String REQUEST_ID = "bower.requestId";
    public static final String CLIENT_IP = "bower.clientIp";
    private final List<String> trusted = Arrays.stream(System.getenv().getOrDefault("TRUSTED_PROXIES", "").split(","))
            .map(String::strip).filter(s -> !s.isEmpty()).toList();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String traceparent = request.getHeader("traceparent");
        String id = traceparent != null && traceparent.length() == 55 ? traceparent.substring(3, 35) : UUID.randomUUID().toString();
        request.setAttribute(REQUEST_ID, id);
        request.setAttribute(CLIENT_IP, BowerEvents.clientIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"), trusted));
        response.setHeader("X-Request-Id", id);
        MDC.put("requestId", id);
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.remove("requestId");
        }
    }
}
