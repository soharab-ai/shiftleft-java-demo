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
@Autowired
private Environment env;

// Security util class to centralize token operations
private static class SecurityUtil {
  private static String getSecretKey(Environment env) {
    // Get key from environment variable or configuration
    String key = env.getProperty("HMAC_SECRET_KEY");
    if (key == null || key.isEmpty()) {
      // Fallback only for development, should be properly configured in production
      key = env.getProperty("hmac.auth.key");
    }
    return key;
  }
  
  public static String generateSignature(Environment env, String data) {
    String key = getSecretKey(env);
    return HmacUtils.hmacSha256Hex(key, data);
  }
  
  public static boolean verifySignature(Environment env, String data, String signature) {
    String expectedSignature = generateSignature(env, data);
    // Use constant-time comparison to prevent timing attacks
    return MessageDigest.isEqual(expectedSignature.getBytes(), signature.getBytes());
  }
  
  public static ObjectMapper getSecureObjectMapper() {
    // Configure Jackson with secure deserialization settings
    return JsonMapper.builder()
      .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
      .activateDefaultTyping(
          BasicPolymorphicTypeValidator.builder()
              .allowIfSubType("io.shiftleft.model")
              .build(),
          ObjectMapper.DefaultTyping.NON_FINAL)
      .build();
  }
}

private boolean isAdmin(String auth)
{
  try {
    // Verify signature before deserializing
    String[] parts = auth.split("\\.");
    if (parts.length != 2) {
      return false;
    }
    
    String data = parts[0];
    String signature = parts[1];
    
    // Verify HMAC signature using constant-time comparison via utility class
    if (!SecurityUtil.verifySignature(env, data, signature)) {
      System.out.println("Invalid signature in auth token");
      return false;
    }
    
    // Use JSON deserialization with secure configuration
    ObjectMapper mapper = SecurityUtil.getSecureObjectMapper();
    AuthToken authToken = mapper.readValue(Base64.getDecoder().decode(data), AuthToken.class);
    return authToken.isAdmin();
  } catch (Exception ex) {
    System.out.println("Cookie cannot be deserialized: " + ex.getMessage());
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
public String doPostLogin(@CookieValue(value = "auth", defaultValue = "notset") String auth, @RequestBody String password, HttpServletResponse response, HttpServletRequest request) throws Exception {
  String succ = "redirect:/admin/printSecrets";

  try {
    // no cookie no fun
    if (!auth.equals("notset")) {
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
      // Create auth token using JSON instead of Java serialization
      AuthToken authToken = new AuthToken(AuthToken.ADMIN);
      
      // Convert to JSON using secure Jackson configuration
      ObjectMapper mapper = SecurityUtil.getSecureObjectMapper();
      String jsonData = mapper.writeValueAsString(authToken);
      
      // Base64 encode the JSON data
      String cookieData = Base64.getEncoder().encodeToString(jsonData.getBytes());
      
      // Sign the cookie data with HMAC using the utility class
      String signature = SecurityUtil.generateSignature(env, cookieData);
      
      // Combine data and signature
      String cookieValue = cookieData + "." + signature;
      
      // Create secure cookie with enhanced security attributes
      Cookie secureAuthCookie = new Cookie("auth", cookieValue);
      secureAuthCookie.setHttpOnly(true);
      secureAuthCookie.setSecure(true);  // Requires HTTPS
      secureAuthCookie.setPath("/");
      secureAuthCookie.setMaxAge(3600);  // 1 hour expiry
      
      // Add SameSite attribute to prevent CSRF
      response.addHeader("Set-Cookie", secureAuthCookie.getName() + "=" + secureAuthCookie.getValue() 
          + "; HttpOnly; Secure; SameSite=Strict; Path=" + secureAuthCookie.getPath()
          + "; Max-Age=" + secureAuthCookie.getMaxAge());
      
      // Add additional security headers
      response.setHeader("X-Content-Type-Options", "nosniff");
      response.setHeader("X-Frame-Options", "DENY");
      response.setHeader("X-XSS-Protection", "1; mode=block");
      
      // cookie is lost after redirection
      request.getSession().setAttribute("auth", cookieValue);

      return succ;
    }
    return fail;
  }
  catch (Exception ex)
  {
    ex.printStackTrace();
    // no succ == fail
    return fail;
  }
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
