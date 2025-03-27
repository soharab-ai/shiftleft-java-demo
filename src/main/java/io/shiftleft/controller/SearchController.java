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
@Controller
public class SearchController {
private static final Logger logger = LoggerFactory.getLogger(SearchController.class);

@RequestMapping(value = "/search/user", method = RequestMethod.GET)
public String doGetSearch(@RequestParam String foo, HttpServletResponse response, HttpServletRequest request) {
    // Set proper Content-Type header for HTML content
    response.setContentType("text/html; charset=UTF-8");
    
    // Implement Content-Security-Policy as a defense-in-depth measure
    response.setHeader("Content-Security-Policy", "default-src 'self'");
    
    // Removed dangerous SpEL parsing of user input
    // Apply proper input validation and sanitization
    String message = validateAndSanitizeInput(foo);
    
    // HTML encode output before returning to prevent XSS
    return StringEscapeUtils.escapeHtml4(message);
}

/**
 * Validates and sanitizes user input to prevent injection attacks
 * Allows more realistic search terms while maintaining security
 */
private String validateAndSanitizeInput(String input) {
    // Implement improved validation logic with more realistic character set
    if (!Pattern.matches("^[a-zA-Z0-9\\s\\-_,.;:'\"]{1,100}$", input)) {
        // Log potential XSS attempts, with proper sanitization of log entries
        logger.warn("Potential XSS attempt detected: " + input.replaceAll("[\r\n]", ""));
        // HTML-escape error messages as well
        return StringEscapeUtils.escapeHtml4("Invalid search input");
    }
    
    // Context-specific encoding for different HTML contexts
    String htmlContextValue = StringEscapeUtils.escapeHtml4(input);
    String attributeContextValue = StringEscapeUtils.escapeHtml4(input);
    String jsContextValue = StringEscapeUtils.escapeEcmaScript(input);
    
    // Return the appropriately escaped value depending on the context
    // For this general case, we use the HTML context value
    return htmlContextValue;
}

    // Initialize the whitelist of operations
    static {
        ALLOWED_OPERATIONS.put("name", new NameSearchOperation());
        ALLOWED_OPERATIONS.put("id", new IdSearchOperation());
        ALLOWED_OPERATIONS.put("email", new EmailSearchOperation());
        // Add more pre-defined operations as needed
    }

    @RequestMapping(value = "/search/user", method = RequestMethod.GET)
    public String doGetSearch(@RequestParam String foo, HttpServletResponse response, HttpServletRequest request) {
        // Replace SpEL with a safer alternative using our custom DSL
        try {
            // Validate and sanitize input
            if (foo == null || foo.trim().isEmpty()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Search query cannot be empty");
            }
            
            // Log the sanitized input for audit purposes
            logger.info("Search request received with query: null", Encode.forJava(foo));
            
            // Parse the query into our domain-specific format
            SearchQuery query = parseSearchQuery(foo);
            
            // Execute the query using our abstraction layer
            String result = searchService.executeQuery(query);
            
            return result != null ? result : "";
            
        } catch (InvalidSearchQueryException e) {
            // Log the exception but don't expose details to the user
            logger.error("Invalid search query: null", Encode.forJava(e.getMessage()));
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid search query format");
        } catch (ResponseStatusException e) {
            // Re-throw the ResponseStatusException
            throw e;
        } catch (Exception e) {
            // Log the exception but don't expose details to the user
            logger.error("Error processing search query", e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "An error occurred while processing your request");
        }
    }
    
    /**
     * Parses the search query into our domain-specific structure
     * 
     * @param query The user-provided query string
     * @return A SearchQuery object representing the parsed query
     * @throws InvalidSearchQueryException If the query is invalid or contains disallowed operations
     */
    private SearchQuery parseSearchQuery(String query) throws InvalidSearchQueryException {
        // Simple DSL format: operation:value
        String[] parts = query.split(":", 2);
        
        if (parts.length != 2) {
            throw new InvalidSearchQueryException("Query must be in format 'operation:value'");
        }
        
        String operation = parts[0].trim().toLowerCase();
        String value = parts[1].trim();
        
        // Check if the operation is in our whitelist
        if (!ALLOWED_OPERATIONS.containsKey(operation)) {
            throw new InvalidSearchQueryException("Operation not allowed: " + Encode.forJava(operation));
        }
        
        // Validate the value format based on the operation
        if (!validateQueryValue(operation, value)) {
            throw new InvalidSearchQueryException("Invalid value format for operation: " + Encode.forJava(operation));
        }
        
        return new SearchQuery(operation, value);
    }
    
    /**
     * Validates the query value based on the operation
     * 
     * @param operation The operation to perform
     * @param value The value to validate
     * @return true if the value is valid for the operation, false otherwise
     */
    private boolean validateQueryValue(String operation, String value) {
        // Apply specific validation rules based on the operation
        if (ALLOWED_OPERATIONS.containsKey(operation)) {
            return ALLOWED_OPERATIONS.get(operation).validateValue(value);
        }
        return false;
    }
    
    /**
     * Domain-specific query class to represent a search query
     */
    public static class SearchQuery {
        private final String operation;
        private final String value;
        
        public SearchQuery(String operation, String value) {
            this.operation = operation;
            this.value = value;
        }
        
        public String getOperation() {
            return operation;
        }
        
        public String getValue() {
            return value;
        }
    }
    
    /**
     * Exception for invalid search queries
     */
    public static class InvalidSearchQueryException extends Exception {
        public InvalidSearchQueryException(String message) {
            super(message);
        }
    }
    
    /**
     * Interface for search operations
     */
    public interface SearchOperation {
        boolean validateValue(String value);
        String execute(String value);
    }
    
    /**
     * Example implementation for name search
     */
    private static class NameSearchOperation implements SearchOperation {
        private static final Pattern NAME_PATTERN = Pattern.compile("^[a-zA-Z\\s]{1,50}$");
        
        @Override
        public boolean validateValue(String value) {
            return value != null && NAME_PATTERN.matcher(value).matches();
        }
        
        @Override
        public String execute(String value) {
            // Implementation for searching by name
            return "User with name: " + value;
        }
    }
    
    /**
     * Example implementation for ID search
     */
    private static class IdSearchOperation implements SearchOperation {
        private static final Pattern ID_PATTERN = Pattern.compile("^[0-9]{1,10}$");
        
        @Override
        public boolean validateValue(String value) {
            return value != null && ID_PATTERN.matcher(value).matches();
        }
        
        @Override
        public String execute(String value) {
            // Implementation for searching by ID
            return "User with ID: " + value;
        }
    }
    
    /**
     * Example implementation for email search
     */
    private static class EmailSearchOperation implements SearchOperation {
        private static final Pattern EMAIL_PATTERN = 
            Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
        
        @Override
        public boolean validateValue(String value) {
            return value != null && EMAIL_PATTERN.matcher(value).matches();
        }
        
        @Override
        public String execute(String value) {
            // Implementation for searching by email
            return "User with email: " + value;
        }
    }
}

/**
 * Service for executing search queries
 */
interface SearchService {
    String executeQuery(SearchController.SearchQuery query);
}

/**
 * Implementation of SearchService
 */
class SearchServiceImpl implements SearchService {
    @Override
    public String executeQuery(SearchController.SearchQuery query) {
        // Get the appropriate operation from the controller's whitelist
        SearchController.SearchOperation operation = 
            SearchController.ALLOWED_OPERATIONS.get(query.getOperation());
        
        // Execute the operation with the query value
        return operation.execute(query.getValue());
    }
}

