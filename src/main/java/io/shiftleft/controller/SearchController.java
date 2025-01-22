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
        // Removed the ExpressionParser and used a whitelist approach to validate the input
        if (!isValidInput(foo)) {
            throw new IllegalArgumentException("Invalid input");
        }
        message = HtmlUtils.htmlEscape(foo); // Use a safer way to set message and escape HTML
    } catch (Exception ex) {
        Logger logger = LoggerFactory.getLogger(SearchController.class);
        logger.error(ex.getMessage());
    }
    return message.toString();
}

private boolean isValidInput(String input) {
    // Implement a whitelist approach to validate the input
    // For example, only allow alphanumeric characters and a select list of allowed characters
    String validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
    for (char c : input.toCharArray()) {
        if (validChars.indexOf(c) == -1) {
            return false;
        }
    }
    return true;
}

    return message.toString();
}

    return message.toString();
  }
}
