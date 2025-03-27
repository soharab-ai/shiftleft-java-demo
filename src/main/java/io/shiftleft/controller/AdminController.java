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
// Secret key retrieved from environment variables instead of hardcoding
@Autowired
private Environment env;

private static final ObjectMapper objectMapper = new ObjectMapper();

// Initialize ObjectMapper with secure configurations
{
    // Apply Jackson security modules
    objectMapper.registerModule(new Jdk8Module());
    // Strict type checking
    objectMapper.activateDefaultTyping(
        new LaissezFaireSubTypeValidator(),
        ObjectMapper.DefaultTyping.NONE,
        JsonTypeInfo.As.PROPERTY
    );
    // Fail on unknown properties
    objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
}

private boolean isAdmin(String auth) {
    try {
        // Split the auth token into data and signature parts
        String[] parts = auth.split("\\.");
        if (parts.length != 2) {
            System.out.println("Invalid token format");
            return false;
        }

        // Verify the signature
        String data = parts[0];
        String signature = parts[1];
        
        // Get secret key from environment variables
        String secretKey = env.getProperty("auth.secret.key");
        if (secretKey == null || secretKey.isEmpty()) {
            System.out.println("Secret key not configured");
            return false;
        }
        
        if (!verifySignature(data, signature, secretKey)) {
            System.out.println("Token signature verification failed");
            return false;
        }

        // Input validation before deserialization
        if (!isValidJsonInput(data)) {
            System.out.println("Invalid input format");
            return false;
        }

        // Decode the data part (base64)
        byte[] decodedBytes = Base64.getDecoder().decode(data);
        String jsonStr = new String(decodedBytes);
        
        // Deserialize JSON to AuthToken
        AuthToken authToken = objectMapper.readValue(jsonStr, AuthToken.class);
        
        // Check token expiration
        if (authToken.getExpirationTime() < Instant.now().getEpochSecond()) {
            System.out.println("Token has expired");
            return false;
        }
        
        return authToken.isAdmin();
    } catch (Exception ex) {
        System.out.println("Token validation failed: " + ex.getMessage());
        return false;
    }
}

private boolean verifySignature(String data, String signature, String secretKey) throws NoSuchAlgorithmException, InvalidKeyException {
    SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(secretKeySpec);
    byte[] computedSignature = mac.doFinal(data.getBytes());
    String computedSignatureStr = Base64.getEncoder().encodeToString(computedSignature);
    return computedSignatureStr.equals(signature);
}

// Input validation method to ensure the data is properly formatted
private boolean isValidJsonInput(String base64Data) {
    try {
        byte[] decodedBytes = Base64.getDecoder().decode(base64Data);
        String jsonStr = new String(decodedBytes);
        // Simple validation to check if it's a JSON object
        return jsonStr.trim().startsWith("{") && jsonStr.trim().endsWith("}") 
            && Pattern.compile("\\{.*\\}").matcher(jsonStr).matches();
    } catch (Exception e) {
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
    String fail = "redirect:/admin/login?error=true";

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
            // Set token expiration time (24 hours from now)
            long expirationTime = Instant.now().plusSeconds(86400).getEpochSecond();
            
            // Create token with expiration
            AuthToken authToken = new AuthToken(AuthToken.ADMIN);
            authToken.setExpirationTime(expirationTime);
            
            // Get secret key from environment variables
            String secretKey = env.getProperty("auth.secret.key");
            if (secretKey == null || secretKey.isEmpty()) {
                System.out.println("Secret key not configured");
                return fail;
            }
            
            // Convert AuthToken to JSON instead of Java serialization
            String jsonStr = objectMapper.writeValueAsString(authToken);
            String base64Data = Base64.getEncoder().encodeToString(jsonStr.getBytes());
            
            // Generate HMAC signature for the token
            String signature = generateSignature(base64Data, secretKey);
            
            // Combine data and signature
            String cookieValue = base64Data + "." + signature;
            
            // Set the secure cookie
            Cookie authCookie = new Cookie("auth", cookieValue);
            authCookie.setHttpOnly(true);
            authCookie.setSecure(true); // For HTTPS environments
            authCookie.setPath("/");
            response.addCookie(authCookie);

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

private String generateSignature(String data, String secretKey) throws NoSuchAlgorithmException, InvalidKeyException {
    SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(secretKeySpec);
    byte[] signature = mac.doFinal(data.getBytes());
    return Base64.getEncoder().encodeToString(signature);
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
