package example.bower.spring;

import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Validation failures and last-resort errors (ASVS 5.0 V16.3.3, V16.3.4, V16.5.1, V16.5.4). */
@RestControllerAdvice
public class BowerErrorHandler {
    private final BowerSecurity bower;

    public BowerErrorHandler(BowerSecurity bower) {
        this.bower = bower;
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, HttpMessageNotReadableException.class})
    public ResponseEntity<Map<String, String>> invalid(Exception error) {
        bower.emit(Map.of("eventCategory", "application-security", "eventType", "input_validation_failure",
                "eventAction", "validation.reject", "eventResult", "failure", "eventSeverity", "low",
                "reason", error.getClass().getSimpleName()));
        return ResponseEntity.badRequest().body(Map.of("error", "bad request"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> unexpected(Exception error) {
        bower.emit(Map.of("eventCategory", "application-security", "eventType", "application_error",
                "eventAction", "error.unhandled", "eventResult", "failure", "eventSeverity", "medium",
                "reason", "UnhandledException", "labels", Map.of("errorType", error.getClass().getSimpleName())));
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "internal error"));
    }
}
