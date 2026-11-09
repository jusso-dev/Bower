package example.bower.spring;

import java.util.Map;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.stereotype.Component;

/**
 * Spring Security events to Bower (ASVS 5.0 V16.3.1, V16.3.2). Spring publishes these when an
 * AuthenticationEventPublisher bean exists (Boot registers DefaultAuthenticationEventPublisher)
 * and, for authorisation, when an AuthorizationEventPublisher bean is declared.
 */
@Component
public class BowerAuthenticationEvents {
    private final BowerSecurity bower;

    public BowerAuthenticationEvents(BowerSecurity bower) {
        this.bower = bower;
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        bower.emit(Map.of("eventCategory", "authentication", "eventType", "authentication_success",
                "eventAction", "authentication.login", "eventResult", "success",
                "actor", Map.of("username", event.getAuthentication().getName()),
                "labels", Map.of("authMethod", event.getAuthentication().getClass().getSimpleName())));
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        // getCredentials() is the submitted password: never read it.
        bower.emit(Map.of("eventCategory", "authentication", "eventType", "authentication_failure",
                "eventAction", "authentication.attempt", "eventResult", "failure", "eventSeverity", "low",
                "reason", event.getException().getClass().getSimpleName(),
                "actor", Map.of("username", String.valueOf(event.getAuthentication().getPrincipal()))));
    }

    @EventListener
    public void onLogout(LogoutSuccessEvent event) {
        bower.emit(Map.of("eventCategory", "authentication", "eventType", "session_terminated",
                "eventAction", "session.logout", "eventResult", "success",
                "actor", Map.of("username", event.getAuthentication().getName())));
    }

    @EventListener
    public void onDenied(AuthorizationDeniedEvent<?> event) {
        var authentication = event.getAuthentication().get();
        bower.emit(Map.of("eventCategory", "authorisation", "eventType", "authorisation_failure",
                "eventAction", "authz.function", "eventResult", "denied", "eventSeverity", "medium",
                "actor", Map.of("username", authentication == null ? "anonymous" : authentication.getName()),
                "target", Map.of("type", "function", "id", event.getSource().getClass().getSimpleName())));
    }
}
