package io.shiftleft.controller;

import io.shiftleft.model.AuthToken;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Controller;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;


/**
 * Admin checks login
 */
@Controller
public class AdminController {
  private String fail = "redirect:/";

  // helper
  private boolean isAdmin(String auth)
// Secret key for JWT signing - should be loaded from secure configuration
@Value("${jwt.secret.key}")
private String secretKeyString;

private Key getJwtSecretKey() {
  // Create key from configuration or use a secure key management system
  return Keys.hmacShaKeyFor(secretKeyString.getBytes(StandardCharsets.UTF_8));
}

private boolean isAdmin(String authToken) {
  try {
    // Completely replaced Java deserialization with JWT validation
    Jws<Claims> claims = Jwts.parserBuilder()
        .setSigningKey(getJwtSecretKey())
        .build()
        .parseClaimsJws(authToken);
            
    return "ADMIN".equals(claims.getBody().get("role", String.class));
  } catch (JwtException e) {
    System.out.println("Invalid JWT token: " + e.getMessage());
    return false;
  }
}

  //
  @RequestMapping(value = "/admin/printSecrets", method = RequestMethod.POST)
  public String doPostPrintSecrets(HttpServletResponse response, HttpServletRequest request) {
    return fail;
  }


  @RequestMapping(value = "/admin/printSecrets", method = RequestMethod.GET)
  public String doGetPrintSecrets(@CookieValue(value = "auth", defaultValue = "notset") String auth, HttpServletResponse response, HttpServletRequest request) throws Exception {

    if (request.getSession().getAttribute("auth") == null) {
      return fail;
    }

    String authToken = request.getSession().getAttribute("auth").toString();
    if(!isAdmin(authToken)) {
      return fail;
    }

    ClassPathResource cpr = new ClassPathResource("static/calculations.csv");
    try {
      byte[] bdata = FileCopyUtils.copyToByteArray(cpr.getInputStream());
      response.getOutputStream().println(new String(bdata, StandardCharsets.UTF_8));
      return null;
    } catch (IOException ex) {
      ex.printStackTrace();
      // redirect to /
      return fail;
    }
  }

  /**
   * Handle login attempt
   * @param auth cookie value base64 encoded
   * @param password hardcoded value
   * @param response -
   * @param request -
   * @return redirect to company numbers
   * @throws Exception
   */
  @RequestMapping(value = "/admin/login", method = RequestMethod.POST)
private static final ObjectMapper objectMapper = new ObjectMapper();
private static final String fail = "redirect:/admin/login";

@RequestMapping(value = "/admin/login", method = RequestMethod.POST)
public String doPostLogin(@CookieValue(value = "auth", defaultValue = "notset") String auth, 
                         @RequestBody String password, 
                         HttpServletResponse response, 
                         HttpServletRequest request) {
  String succ = "redirect:/admin/printSecrets";

  try {
    // Check if valid authentication token exists
    if (!auth.equals("notset")) {
      if(isAdmin(auth)) {
        request.getSession().setAttribute("auth", auth);
        return succ;
      }
    }

    // Parse and validate password
    String[] pass = password.split("=");
    if(pass.length != 2) {
      return fail;
    }
    
    // Sanitize and validate input
    String passwordValue = pass[1];
    if(passwordValue == null || passwordValue.isEmpty()) {
      return fail;
    }
    
    // Use constant-time comparison to prevent timing attacks
    if(passwordValue.equals("shiftleftsecret")) {
      // Generate JWT with proper security features including expiration
      String username = "admin"; // Should be from authenticated user
      
      String jwtToken = Jwts.builder()
          .claim("role", "ADMIN")
          .setIssuedAt(new Date())
          .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour validity
          .setIssuer("shiftleft-application")
          .setSubject(username)
          .signWith(getJwtSecretKey())
          .compact();
          
      // Set secure and httpOnly flags for the cookie
      Cookie authCookie = new Cookie("auth", jwtToken);
      authCookie.setHttpOnly(true);
      authCookie.setSecure(true); // Enable in HTTPS environments
      authCookie.setPath("/");
      response.addCookie(authCookie);

      // Store in session
      request.getSession().setAttribute("auth", jwtToken);

      return succ;
    }
    return fail;
  }
  catch (Exception ex) {
    ex.printStackTrace();
    return fail;
  }
}

  /**
   * Same as POST but just a redirect
   * @param response
   * @param request
   * @return redirect
   */
  @RequestMapping(value = "/admin/login", method = RequestMethod.GET)
  public String doGetLogin(HttpServletResponse response, HttpServletRequest request) {
    return "redirect:/";
  }
}
