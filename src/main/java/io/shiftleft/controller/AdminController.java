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
// FIX: Replaced insecure Java deserialization with secure JWT token validation
private boolean isAdmin(String auth)
  {
    try {
      // FIX: Add input validation to prevent malformed input from reaching JWT parser
      if (auth == null || auth.isEmpty() || !auth.matches("^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$")) {
        System.out.println("Invalid token format");
        return false;
      }
      
      // FIX: Using JWT parser with signature verification and issuer/audience validation
      Claims claims = Jwts.parserBuilder()
          .setSigningKey(getSecretKey())
          .requireIssuer("AdminController")
          .requireAudience("admin-service")
          .build()
          .parseClaimsJws(auth)
          .getBody();
      // FIX: Extract admin claim from validated JWT token
      Boolean isAdmin = claims.get("admin", Boolean.class);
      return isAdmin != null && isAdmin;
    } catch (Exception ex) {
      // FIX: Generic error message to prevent information leakage
      System.out.println("Invalid or tampered token");
      return false;
    }
  }

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
  public String doPostLogin(@CookieValue(value = "auth", defaultValue = "notset") String auth, @RequestBody String password, HttpServletResponse response, HttpServletRequest request) throws Exception {
    String succ = "redirect:/admin/printSecrets";

    try {
      // no cookie no fun
      if (!auth.equals("notset")) {
        // FIX: isAdmin now validates JWT token instead of deserializing objects
        if(isAdmin(auth)) {
          request.getSession().setAttribute("auth",auth);
          return succ;
        }
      }

      // split password=value
      String[] pass = password.split("=");
      if(pass.length!=2) {
        return fail;
      }
      // compare pass
      if(pass[1] != null && pass[1].length()>0 && pass[1].equals("shiftleftsecret"))
      {
        // FIX: Generate secure JWT token with user identity instead of serializing AuthToken object
        String cookieValue = generateAuthToken(true, "admin");
        
        // FIX: Set secure cookie attributes to prevent token theft
        Cookie authCookie = new Cookie("auth", cookieValue);
        authCookie.setHttpOnly(true);
        authCookie.setSecure(true);
        authCookie.setPath("/");
        response.addCookie(authCookie);

        // cookie is lost after redirection
        request.getSession().setAttribute("auth",cookieValue);

        return succ;
      }
      return fail;
    }
    catch (Exception ex)
    {
      ex.printStackTrace();
      // no succ == fail
// FIX: New method to generate secure JWT tokens with expiration, issuer, audience, and subject claims
private String generateAuthToken(boolean isAdmin, String username) {
    try {
      // FIX: Add token expiration to limit validity window (15 minutes)
      long expirationMillis = System.currentTimeMillis() + (15 * 60 * 1000);
      Date expirationDate = new Date(expirationMillis);
      
      // FIX: Create JWT with admin claim, user identity, expiration, issuer, and audience
      return Jwts.builder()
          .setSubject(username)
          .claim("admin", isAdmin)
          .setIssuer("AdminController")
          .setAudience("admin-service")
          .setIssuedAt(new Date())
          .setExpiration(expirationDate)
          .signWith(getSecretKey(), SignatureAlgorithm.HS256)
          .compact();
    } catch (Exception ex) {
      throw new RuntimeException("Failed to generate authentication token", ex);
    }
  }
// FIX: Secure key management for JWT signing and validation
private static SecretKey SECRET_KEY = null;
  
  private Key getSecretKey() {
    // FIX: Load key from environment variable for production use, with fallback and warning
    if (SECRET_KEY == null) {
      String keyString = System.getenv("JWT_SECRET_KEY");
      
      if (keyString == null || keyString.isEmpty()) {
        System.err.println("CRITICAL SECURITY WARNING: JWT_SECRET_KEY environment variable not set. Using generated key that will invalidate all tokens on restart. This configuration is UNSAFE for production.");
        SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
      } else {
        // FIX: Load persistent key from environment variable to prevent token invalidation on restart
        byte[] decodedKey = Base64.getDecoder().decode(keyString);
        SECRET_KEY = Keys.hmacShaKeyFor(decodedKey);
      }
    }
    return SECRET_KEY;
  }
