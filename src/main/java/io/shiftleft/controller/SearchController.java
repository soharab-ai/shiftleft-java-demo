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
@Validated
public String doGetSearch(
    @RequestParam @Pattern(regexp="^[a-zA-Z0-9]+$") String foo, 
    @RequestParam(defaultValue = "DEFAULT") String operation,
    HttpServletResponse response, 
    HttpServletRequest request) {

  // Completely eliminated SpEL in favor of direct function mapping
  Map<String, Function<String, String>> safeOperations = new HashMap<>();
  
  // Define allowed operations with corresponding safe implementations
  safeOperations.put("DEFAULT", input -> input);
  safeOperations.put("UPPERCASE", String::toUpperCase);
  safeOperations.put("LOWERCASE", String::toLowerCase);
  safeOperations.put("LENGTH", input -> String.valueOf(input.length()));
  safeOperations.put("TRIM", String::trim);
  
  // Attempt to find the requested operation in our safe operations map
  Function<String, String> selectedOperation = safeOperations.get(operation.toUpperCase());
  
  // If operation isn't in our whitelist, return an error message
  if (selectedOperation == null) {
    return "Unsupported operation. Available operations: " + 
           String.join(", ", safeOperations.keySet());
  }
  
  try {
    // Apply the selected operation to the input
    String result = selectedOperation.apply(foo);
    return result != null ? result : "";
  } catch (Exception ex) {
    // Log exception safely (without exposing details to the user)
    System.out.println("Error processing operation: " + operation);
    return "Error processing your request";
  }
}

    return message.toString();
  }
}
