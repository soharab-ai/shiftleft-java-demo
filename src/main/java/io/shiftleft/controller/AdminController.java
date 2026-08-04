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
/**
 * FIXED: Revokes a token by removing it from the active token cache
 * Allows immediate invalidation of compromised tokens before natural expiration
 * 
 * @param tokenId The unique token identifier (jti) to revoke
 * @return true if successfully revoked, false otherwise
 */
public boolean revokeToken(String tokenId) {
  try {
    if (redisTemplate != null) {
      redisTemplate.delete("jwt:active:" + tokenId);
      return true;
    }
    return false;
  } catch (Exception ex) {
    System.err.println("Failed to revoke token: " + ex.getMessage());
    return false;
  }
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
      // FIXED: Use JWT token validation instead of insecure deserialization
      if (!auth.equals("notset")) {
        if(isAdmin(auth)) {
// FIXED: Rate limiting state management
private static final ConcurrentHashMap<String, Integer> failedAttempts = new ConcurrentHashMap<>();
private static final ConcurrentHashMap<String, Long> attemptTimestamps = new ConcurrentHashMap<>();
private static final int MAX_ATTEMPTS = 5;
private static final long LOCKOUT_DURATION_MS = 900000; // 15 minutes

/**
 * FIXED: Checks if client IP is rate limited due to excessive failed login attempts
 * 
 * @param clientIP The IP address of the client
 * @return true if rate limited, false otherwise
 */
private boolean isRateLimited(String clientIP) {
  Integer attempts = failedAttempts.get(clientIP);
  Long lockoutTime = attemptTimestamps.get(clientIP);
  
  if (attempts != null && attempts >= MAX_ATTEMPTS) {
    if (lockoutTime != null && System.currentTimeMillis() - lockoutTime < LOCKOUT_DURATION_MS) {
      return true; // Still in lockout period
    } else {
      // Lockout period expired, reset attempts
      resetFailedAttempts(clientIP);
    }
  }
  return false;
}

      if(pass[1] != null && pass[1].length()>0 && isPasswordValid(pass[1], "shiftleftsecret"))
      {
        // FIXED: Generate secure JWT token with enhanced claims (jti, iss, aud, nbf, sub)
        // Derive userId from session or authentication context
        String userId = (String) request.getSession().getAttribute("userId");
        if (userId == null) {
          userId = "admin-" + System.currentTimeMillis(); // Fallback if userId not in session
        }
        
        String jwtToken = generateAuthToken(true, userId);
        
        // FIXED: Add secure cookie flags including SameSite to prevent XSS and CSRF attacks
        Cookie authCookie = new Cookie("auth", jwtToken);
        authCookie.setHttpOnly(true);  // Prevents JavaScript access
        authCookie.setSecure(true);    // HTTPS only
        authCookie.setPath("/");
        authCookie.setMaxAge(3600);    // 1 hour expiration
        authCookie.setAttribute("SameSite", "Strict"); // FIXED: Prevent CSRF attacks
        response.addCookie(authCookie);

        // cookie is lost after redirection
        request.getSession().setAttribute("auth", jwtToken);

        // FIXED: Reset failed attempts on successful login
        resetFailedAttempts(clientIP);

        return succ;
      }
      // FIXED: Record failed login attempt
      recordFailedAttempt(clientIP);
      return fail;
    }
    catch (Exception ex)
    {
      // FIXED: Log exception securely without exposing stack trace to user
      System.err.println("Login error: " + ex.getMessage());
      // no succ == fail
@Autowired(required = false)
private RedisTemplate<String, String> redisTemplate;

/**
 * FIXED: Stores active token ID in cache for revocation capability
 * Uses Redis for distributed token management across application instances
 * 
 * @param tokenId The unique token identifier (jti)
 * @param ttlSeconds Time-to-live in seconds matching token expiration
 */
private void storeActiveToken(String tokenId, long ttlSeconds) {
  try {
    if (redisTemplate != null) {
      redisTemplate.opsForValue().set("jwt:active:" + tokenId, "valid", ttlSeconds, TimeUnit.SECONDS);
    }
  } catch (Exception ex) {
    System.err.println("Failed to store active token: " + ex.getMessage());
  }
}
