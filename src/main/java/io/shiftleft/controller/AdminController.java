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
private boolean isAdmin(String auth) {
    try {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSecretKey())
                .build()
                .parseClaimsJws(auth)
                .getBody();
        
        return claims.containsKey("role") && "ADMIN".equals(claims.get("role", String.class));
    } catch (Exception ex) {
        System.out.println("Invalid authentication token: " + ex.getMessage());
        return false;
    }
}

private String createJwtToken(boolean isAdmin) {
    long nowMillis = System.currentTimeMillis();
    Date now = new Date(nowMillis);
    Date expiration = new Date(nowMillis + 3600000); // 1 hour
    
    return Jwts.builder()
            .setIssuedAt(now)
            .setExpiration(expiration)
            .claim("role", isAdmin ? "ADMIN" : "USER")
            .signWith(getSecretKey())
            .compact();
}

private SecretKey getSecretKey() {
    // In a real application, this key should be stored securely (e.g., environment variables, vault)
    // and should be at least 256 bits for HS256
    String secretKeyString = "YourSecretKeyHereMakeSureItIsAtLeast32BytesLong";
    return Keys.hmacShaKeyFor(secretKeyString.getBytes());
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
public String doPostLogin(@CookieValue(value = "auth", defaultValue = "notset") String auth, 
                          @RequestBody String password, 
                          HttpServletResponse response, 
                          HttpServletRequest request) throws Exception {
    String succ = "redirect:/admin/printSecrets";

    try {
        // no cookie no fun
        if (!auth.equals("notset")) {
            if(isAdmin(auth)) {
                request.getSession().setAttribute("auth", auth);
                return succ;
            }
        }

        // split password=value
        String[] pass = password.split("=");
        if(pass.length != 2) {
            return fail;
        }
        
        // compare pass
        if(pass[1] != null && pass[1].length() > 0 && pass[1].equals("shiftleftsecret")) {
            // Create a secure JWT token instead of using Java serialization
            String jwtToken = createJwtToken(true);
            
            // Set the JWT token as a cookie
            Cookie authCookie = new Cookie("auth", jwtToken);
            authCookie.setHttpOnly(true);
            authCookie.setSecure(true); // Enable in HTTPS environments
            authCookie.setPath("/");
            authCookie.setMaxAge(3600); // 1 hour
            response.addCookie(authCookie);
            
            // Store in session
            request.getSession().setAttribute("auth", jwtToken);
            
            return succ;
        }
        return fail;
    } catch (Exception ex) {
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
