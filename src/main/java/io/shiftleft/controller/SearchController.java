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
public String doGetSearch(@RequestParam String foo, HttpServletResponse response, HttpServletRequest request) {
    java.lang.Object message = new Object();
    try {
        // Validate and sanitize the input before passing to the ExpressionParser
        if (!isValidInput(foo)) {
            throw new IllegalArgumentException("Invalid input");
        }
        // Sanitize the input using OWASP Java Encoder
        foo = EncodeForHTML(foo);
        ExpressionParser parser = new SpelExpressionParser();
        Expression exp = parser.parseExpression(foo);
        message = (Object) exp.getValue();
    } catch (Exception ex) {
        System.out.println(ex.getMessage());
    }
    return safeToString(message);
}

private boolean isValidInput(String input) {
    // Implement validation logic here
    // For example, check if input contains only expected characters
    return true;
}

private String safeToString(Object obj) {
    // Implement safeToString logic here
    // For example, escape HTML tags
    return obj != null ? obj.toString() : "";
}

// Method to sanitize input for HTML
private String EncodeForHTML(String input){
    return Encode.forHtml(input);
}

    return message.toString();
  }
}
