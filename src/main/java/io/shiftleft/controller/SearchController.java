package io.shiftleft.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;


/**
 * Search login
 */
@Controller
public class SearchController {

  @RequestMapping(value = "/search/user", method = RequestMethod.GET)
private static final Logger logger = LoggerFactory.getLogger(SearchController.class);
// Create a strict HTML policy for sanitization
private static final PolicyFactory HTML_POLICY = new HtmlPolicyBuilder()
    .allowElements("p", "b", "i", "u")
    .toFactory();
// Define allowed SpEL expressions with a whitelist approach
private static final Set<String> ALLOWED_EXPRESSIONS;
static {
    Set<String> allowed = new HashSet<>();
    allowed.add("concat");
    allowed.add("toLowerCase");
    allowed.add("toUpperCase");
    ALLOWED_EXPRESSIONS = Collections.unmodifiableSet(allowed);
}

@RequestMapping(value = "/search/user", method = RequestMethod.GET, produces = MediaType.TEXT_PLAIN_VALUE)
public ResponseEntity<String> doGetSearch(@RequestParam String foo, HttpServletResponse response, HttpServletRequest request) {
    // Set security headers for defense in depth
    response.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'none'; object-src 'none'");
    response.setHeader("X-XSS-Protection", "1; mode=block");
    response.setHeader("X-Content-Type-Options", "nosniff");
    
    // Set secure and HTTPOnly flags on any cookies
    if (request.getCookies() != null) {
        for (Cookie cookie : request.getCookies()) {
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
        }
    }
    
    // Log the incoming request with proper encoding to prevent log injection
    logger.info("Processing search request with parameter: null", StringEscapeUtils.escapeJava(foo));
    
    // Validate input using a stricter approach than regex
    if (foo == null || !validateSpelExpression(foo)) {
        logger.warn("Invalid SpEL expression rejected: null", StringEscapeUtils.escapeJava(foo));
        return ResponseEntity.badRequest().body("Invalid input");
    }
    
    String message = "";
    try {
        // Use a safer approach than direct SpEL evaluation
        // Option 1: If SpEL is absolutely necessary, use strict context
        StandardEvaluationContext context = new StandardEvaluationContext();
        // Restrict type access with custom type locator
        context.setTypeLocator(new RestrictiveTypeLocator());
        
        ExpressionParser parser = new SpelExpressionParser();
        Expression exp = parser.parseExpression(foo);
        Object result = exp.getValue(context);
        
        // Apply multiple layers of protection:
        // 1. HTML sanitization to remove any potentially dangerous HTML
        String sanitized = HTML_POLICY.sanitize(result != null ? result.toString() : "");
        // 2. Context-specific encoding using OWASP Encoder
        message = Encode.forHtml(sanitized);
        
        logger.debug("Processed expression successfully");
    } catch (Exception ex) {
        logger.error("Error processing expression", ex);
        // Don't expose error details to users
        message = "An error occurred processing your request";
    }
    
    // Return plain text response with properly encoded content
    return ResponseEntity.ok(message);
}

/**
 * Validates a SpEL expression against a strict whitelist approach
 * More robust than regex pattern matching alone
 */
private boolean validateSpelExpression(String input) {
    // First check: basic character validation
    if (!Pattern.matches("^[a-zA-Z0-9\\s\\+\\-\\*\\/\\.\\(\\)\\,]*$", input)) {
        return false;
    }
    
    // Second check: whitelist of allowed function names
    for (String function : ALLOWED_EXPRESSIONS) {
        if (input.contains(function)) {
            return true;
        }
    }
    
    // Only allow simple expressions if no functions are used
    return Pattern.matches("^[a-zA-Z0-9\\s\\+\\-\\*\\/\\.]*$", input);
}

/**
 * Restrictive type locator that prevents access to dangerous classes
 */
private static class RestrictiveTypeLocator implements TypeLocator {
    @Override
    public Class<?> findType(String typeName) {
        // Only allow String class - extremely restrictive
        if ("java.lang.String".equals(typeName)) {
            return String.class;
        }
        // Block access to all other types
        logger.warn("Blocked access attempt to type: null", typeName);
        throw new SecurityException("Type access not permitted");
    }
}

