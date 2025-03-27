package io.shiftleft.controller;

import io.shiftleft.model.Account;
import io.shiftleft.model.Address;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import java.util.Set;
import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.HttpHeaders;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.WebRequest;

import com.ulisesbocchio.jasyptspringboot.annotation.EnableEncryptableProperties;

import io.shiftleft.data.DataLoader;
import io.shiftleft.exception.CustomerNotFoundException;
import io.shiftleft.exception.InvalidCustomerRequestException;
import io.shiftleft.model.Customer;
import io.shiftleft.repository.CustomerRepository;

import org.springframework.web.util.HtmlUtils;

/**
 * Customer Controller exposes a series of RESTful endpoints
 */

@Configuration
@EnableEncryptableProperties
@PropertySource({ "classpath:config/application-sfdc.properties" })
@RestController
public class CustomerController {

	@Autowired
	private CustomerRepository customerRepository;

	@Autowired
	Environment env;
	
	private static Logger log = LoggerFactory.getLogger(CustomerController.class);

	@PostConstruct
	public void init() {
		log.info("Start Loading SalesForce Properties");
		log.info("Url is {}", env.getProperty("sfdc.url"));
		log.info("UserName is {}", env.getProperty("sfdc.username"));
		log.info("Password is {}", env.getProperty("sfdc.password"));
		log.info("End Loading SalesForce Properties");
	}

	private void dispatchEventToSalesForce(String event)
			throws ClientProtocolException, IOException, AuthenticationException {
		CloseableHttpClient client = HttpClients.createDefault();
		HttpPost httpPost = new HttpPost(env.getProperty("sfdc.url"));
		httpPost.setEntity(new StringEntity(event));
		UsernamePasswordCredentials creds = new UsernamePasswordCredentials(env.getProperty("sfdc.username"),
				env.getProperty("sfdc.password"));
		httpPost.addHeader(new BasicScheme().authenticate(creds, httpPost, null));

		CloseableHttpResponse response = client.execute(httpPost);
		log.info("Response from SFDC is {}", response.getStatusLine().getStatusCode());
		client.close();
	}

	/**
	 * Get customer using id. Returns HTTP 404 if customer not found
	 *
	 * @param customerId
	 * @return retrieved customer
	 */
	@RequestMapping(value = "/customers/{customerId}", method = RequestMethod.GET)
	public Customer getCustomer(@PathVariable("customerId") Long customerId) {

		/* validate customer Id parameter */
      if (null == customerId) {
        throw new InvalidCustomerRequestException();
      }

      Customer customer = customerRepository.findOne(customerId);
		if (null == customer) {
		  throw new CustomerNotFoundException();
	  }

	  Account account = new Account(4242l,1234, "savings", 1, 0);
	  log.info("Account Data is {}", account);
	  log.info("Customer Data is {}", customer);

      try {
        dispatchEventToSalesForce(String.format(" Customer %s Logged into SalesForce", customer));
      } catch (Exception e) {
        log.error("Failed to Dispatch Event to SalesForce . Details {} ", e.getLocalizedMessage());

      }

      return customer;
    }

    /**
     * Handler for / loads the index.tpl
     * @param httpResponse
     * @param request
     * @return
     * @throws IOException
     */
      @RequestMapping(value = "/", method = RequestMethod.GET)
      public String index(HttpServletResponse httpResponse, WebRequest request) throws IOException {
	  	ClassPathResource cpr = new ClassPathResource("static/index.html");
	  	String ret = "";
		  try {
			  byte[] bdata = FileCopyUtils.copyToByteArray(cpr.getInputStream());
			  ret= new String(bdata, StandardCharsets.UTF_8);
		  } catch (IOException e) {
			  //LOG.warn("IOException", e);
		  }
		  return ret;
      }

      /**
       * Check if settings= is present in cookie
       * @param request
       * @return
       */
      private boolean checkCookie(WebRequest request) throws Exception {
      	try {
			return request.getHeader("Cookie").startsWith("settings=");
		}
		catch (Exception ex)
		{
			System.out.println(ex.getMessage());
		}
		return false;
      }

      /**
       * restores the preferences on the filesystem
       *
       * @param httpResponse
       * @param request
       * @throws Exception
       */
      @RequestMapping(value = "/loadSettings", method = RequestMethod.GET)
      public void loadSettings(HttpServletResponse httpResponse, WebRequest request) throws Exception {
        // get cookie values
        if (!checkCookie(request)) {
          httpResponse.getOutputStream().println("Error");
          throw new Exception("cookie is incorrect");
        }
        String md5sum = request.getHeader("Cookie").substring("settings=".length(), 41);
    	ClassPathResource cpr = new ClassPathResource("static");
    	File folder = new File(cpr.getPath());
		File[] listOfFiles = folder.listFiles();
        String filecontent = new String();
        for (File f : listOfFiles) {
          // not efficient, i know
          filecontent = new String();
          byte[] encoded = Files.readAllBytes(f.toPath());
          filecontent = new String(encoded, StandardCharsets.UTF_8);
          if (filecontent.contains(md5sum)) {
            // this will send me to the developer hell (if exists)

            // encode the file settings, md5sum is removed
            String s = new String(Base64.getEncoder().encode(filecontent.replace(md5sum, "").getBytes()));
            // setting the new cookie
            httpResponse.setHeader("Cookie", "settings=" + s + "," + md5sum);
            return;
          }
        }
      }


  /**
   * Saves the preferences (screen resolution, language..) on the filesystem
   *
   * @param httpResponse
   * @param request
   * @throws Exception
   */
  @RequestMapping(value = "/saveSettings", method = RequestMethod.GET)
// Allowed file types mapping with corresponding filesystem locations
private static final Map<String, String> ALLOWED_FILE_TYPES = new HashMap<>();
static {
  ALLOWED_FILE_TYPES.put("user_settings", "settings/user");
  ALLOWED_FILE_TYPES.put("app_settings", "settings/application");
  ALLOWED_FILE_TYPES.put("system_settings", "settings/system");
}

// Maximum file size in bytes (1MB)
private static final int MAX_FILE_SIZE = 1_048_576;

// Storage service for file operations
@Autowired
private StorageService storageService;

// ESAPI Logger for secure logging
private final Logger logger = ESAPI.getLogger(getClass());

@RequestMapping(value = "/saveSettings", method = RequestMethod.GET)
public void saveSettings(HttpServletResponse httpResponse, WebRequest request) throws Exception {
  try {
    // "Settings" will be stored in a cookie
    // schema: base64(fileType,value1,value2...), md5sum(base64(fileType,value1,value2...))

    if (!checkCookie(request)) {
      httpResponse.getOutputStream().println("Error: Invalid authentication");
      logger.error(Logger.SECURITY_FAILURE, "Cookie validation failed in saveSettings");
      throw new SecurityException("Cookie authentication failed");
    }

    String settingsCookie = request.getHeader("Cookie");
    // Sanitize input using ESAPI
    String sanitizedCookie = ESAPI.encoder().encodeForHTML(settingsCookie);
    
    String[] cookie = sanitizedCookie.split(",");
    if (cookie.length < 2) {
      httpResponse.getOutputStream().println("Error: Invalid request format");
      logger.warning(Logger.SECURITY_FAILURE, "Malformed cookie detected: {0}", sanitizedCookie);
      throw new SecurityException("Invalid cookie format");
    }

    String base64txt = cookie[0].replace("settings=", "");

    // Check md5sum
    String cookieMD5sum = cookie[1];
    String calcMD5Sum = DigestUtils.md5Hex(base64txt);
    if (!cookieMD5sum.equals(calcMD5Sum)) {
      httpResponse.getOutputStream().println("Error: Data integrity check failed");
      logger.warning(Logger.SECURITY_FAILURE, "MD5 validation failed for settings");
      throw new SecurityException("Invalid MD5 hash");
    }

    // Now we can process the data
    String decodedSettings = new String(Base64.getDecoder().decode(base64txt));
    // Mark as tainted input and sanitize
    String sanitizedSettings = ESAPI.encoder().encodeForHTML(decodedSettings);
    String[] settings = sanitizedSettings.split(",");
    
    if (settings.length < 2) {
      httpResponse.getOutputStream().println("Error: Invalid settings format");
      logger.warning(Logger.SECURITY_FAILURE, "Invalid settings format");
@RequestMapping(value = "/debug", method = RequestMethod.GET, produces = MediaType.TEXT_HTML_VALUE)
@PreAuthorize("hasRole('ADMIN')") // Added authorization control
@Profile("dev") // Restricted to development environment only
@Validated
public String debug(
        @RequestParam @Pattern(regexp = "^[A-Za-z0-9]{1,50}$", message = "Invalid customer ID format") String customerId,
        @RequestParam int clientId,
        @RequestParam @Pattern(regexp = "^[A-Za-z- ']{1,50}$", message = "Invalid first name") String firstName,
        @RequestParam @Pattern(regexp = "^[A-Za-z- ']{1,50}$", message = "Invalid last name") String lastName,
        @RequestParam @Pattern(regexp = "^\\d{4}-\\d{2}-\\d{2}$", message = "Invalid date format (YYYY-MM-DD)") String dateOfBirth,
        @RequestParam @Pattern(regexp = "^\\d{3}-\\d{2}-\\d{4}$", message = "Invalid SSN format") String ssn,
        @RequestParam @Pattern(regexp = "^\\d{3}-\\d{2}-\\d{4}$", message = "Invalid Social Security Number format") String socialSecurityNum,
        @RequestParam @Pattern(regexp = "^\\d{9}$", message = "Invalid TIN format") String tin,
        @RequestParam @Pattern(regexp = "^\\d{3}-\\d{3}-\\d{4}$", message = "Invalid phone number format") String phoneNumber,
        HttpServletResponse httpResponse,
        WebRequest request) throws IOException {

    // Input validation before processing
    validateCustomerData(customerId, firstName, lastName, dateOfBirth, ssn, socialSecurityNum, tin, phoneNumber);

    Set<Account> accounts1 = new HashSet<Account>();
    //dateofbirth example -> "1982-01-10"
    LocalDate birthDate = LocalDate.parse(dateOfBirth);
    Customer customer1 = new Customer(customerId, clientId, firstName, lastName, java.sql.Date.valueOf(birthDate),
                                      ssn, socialSecurityNum, tin, phoneNumber, new Address("Debug str",
                                      "", "Debug city", "CA", "12345"),
                                      accounts1);

    customerRepository.save(customer1);
    httpResponse.setStatus(HttpStatus.CREATED.value());
    httpResponse.setHeader("Location", String.format("%s/customers/%s",
                           request.getContextPath(), customer1.getId()));
    
    // Enhanced security headers
    httpResponse.setHeader("Content-Security-Policy", 
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; " +
        "font-src 'self'; connect-src 'self'; frame-src 'none'; object-src 'none';");
    httpResponse.setHeader("X-XSS-Protection", "1; mode=block");
    httpResponse.setHeader("X-Content-Type-Options", "nosniff");
    
    // Creating structured HTML response with properly encoded fields instead of toString()
    return generateStructuredHtmlResponse(customer1);
}

/**
 * Validates customer data beyond annotation-based validation
 */
private void validateCustomerData(String customerId, String firstName, String lastName, 
                                 String dateOfBirth, String ssn, String socialSecurityNum, 
                                 String tin, String phoneNumber) {
    // Additional complex validation logic can be implemented here
    // For example, checking if date is valid, not in the future, etc.
    LocalDate birthDate = LocalDate.parse(dateOfBirth);
    if (birthDate.isAfter(LocalDate.now())) {
        throw new IllegalArgumentException("Date of birth cannot be in the future");
    }
}

/**
 * Generates a structured HTML response with properly encoded customer data
 */
private String generateStructuredHtmlResponse(Customer customer) {
    StringBuilder html = new StringBuilder();
    html.append("<!DOCTYPE html><html><head><title>Customer Debug Information</title>");
    html.append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\">");
    html.append("</head><body>");
    html.append("<h1>Customer Information</h1>");
    html.append("<div><strong>ID:</strong> ").append(Encode.forHtml(customer.getId())).append("</div>");
    html.append("<div><strong>Client ID:</strong> ").append(customer.getClientId()).append("</div>");
    html.append("<div><strong>Name:</strong> ").append(Encode.forHtml(customer.getFirstName()))
        .append(" ").append(Encode.forHtml(customer.getLastName())).append("</div>");
    html.append("<div><strong>Date of Birth:</strong> ").append(Encode.forHtml(customer.getDateOfBirth().toString())).append("</div>");
    
    // Don't display full SSN/TIN in HTML - mask sensitive data
    html.append("<div><strong>SSN:</strong> XXX-XX-").append(Encode.forHtml(customer.getSsn().substring(7))).append("</div>");
    html.append("<div><strong>Phone:</strong> ").append(Encode.forHtml(customer.getPhoneNumber())).append("</div>");
    
    if (customer.getAddress() != null) {
        html.append("<h2>Address</h2>");
        html.append("<div>").append(Encode.forHtml(customer.getAddress().getStreet())).append("</div>");
        html.append("<div>").append(Encode.forHtml(customer.getAddress().getCity())).append(", ")
            .append(Encode.forHtml(customer.getAddress().getState())).append(" ")
            .append(Encode.forHtml(customer.getAddress().getZipcode())).append("</div>");
    }
    
    html.append("</body></html>");
    return html.toString();
}

    socialSecurityNum = sanitizeInput(socialSecurityNum);
    tin = sanitizeInput(tin);
    phoneNumber = sanitizeInput(phoneNumber);
    
    // Apply contextual output encoding as defense-in-depth measure
    firstName = StringEscapeUtils.escapeHtml4(firstName);
    lastName = StringEscapeUtils.escapeHtml4(lastName);
    customerId = StringEscapeUtils.escapeHtml4(customerId);
    ssn = StringEscapeUtils.escapeHtml4(ssn);
    socialSecurityNum = StringEscapeUtils.escapeHtml4(socialSecurityNum);
    tin = StringEscapeUtils.escapeHtml4(tin);
    phoneNumber = StringEscapeUtils.escapeHtml4(phoneNumber);

    // empty for now, because we debug
    Set<Account> accounts1 = new HashSet<Account>();
    //dateofbirth example -> "1982-01-10"
    
    // Parse date using java.time API instead of Joda Time
    Date birthDate = Date.from(LocalDate.parse(dateOfBirth).atStartOfDay().toInstant(java.time.ZoneOffset.UTC));
    
    Customer customer1 = new Customer(customerId, clientId, firstName, lastName, birthDate,
                                    ssn, socialSecurityNum, tin, phoneNumber, new Address("Debug str",
                                    "", "Debug city", "CA", "12345"),
                                    accounts1);

    customerRepository.save(customer1);
    httpResponse.setStatus(HttpStatus.CREATED.value());
    httpResponse.setHeader("Location", String.format("%s/customers/%s",
                        request.getContextPath(), customer1.getId()));
    
    // Set security headers to prevent XSS attacks
    httpResponse.setHeader("Content-Security-Policy", "default-src 'self'");
    httpResponse.setHeader("X-Content-Type-Options", "nosniff");
    // Add X-XSS-Protection header to enable browser's XSS filters
    httpResponse.setHeader("X-XSS-Protection", "1; mode=block");
    
    // Implement response type verification
    if (!MediaType.APPLICATION_JSON_VALUE.equals(httpResponse.getContentType())) {
        httpResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
    }
    
    // Configure ObjectMapper to prevent JSON Hijacking
    ObjectMapper objectMapper = new ObjectMapper();
    objectMapper.configure(JsonGenerator.Feature.QUOTE_FIELD_NAMES, true);
    objectMapper.configure(MapperFeature.ESCAPE_NON_ASCII, true);
    
    // Return JSON response instead of raw toString() output
    return objectMapper.writeValueAsString(customer1);
}

// Private helper method for input validation
private boolean validateInputs(String customerId, String firstName, String lastName, 
                               String dateOfBirth, String ssn, String socialSecurityNum, 
                               String tin, String phoneNumber) {
    // Check for null values
    if (customerId == null || firstName == null || lastName == null || 
        dateOfBirth == null || ssn == null || socialSecurityNum == null || 
        tin == null || phoneNumber == null) {
        return false;
    }
    
    // Validate date format (YYYY-MM-DD)
    Pattern datePattern = Pattern.compile("^\\d{4}-\\d{2}-\\d{2}$");
    if (!datePattern.matcher(dateOfBirth).matches()) {
        return false;
    }
    
    // Check if customer ID is not empty
    if (customerId.trim().isEmpty()) {
        return false;
    }
    
    // Additional validation could be implemented based on business requirements
    
    return true;
}

// New method for input sanitization to remove potentially dangerous characters
private String sanitizeInput(String input) {
    if (input == null) {
        return "";
    }
    return input.replaceAll("[<>\"'&]", "");
}

    
    // Sanitize all inputs before database storage
    String sanitizedFirstName = HtmlUtils.htmlEscape(firstName);
    String sanitizedLastName = HtmlUtils.htmlEscape(lastName);
    String sanitizedCustomerId = HtmlUtils.htmlEscape(customerId);
    String sanitizedSSN = HtmlUtils.htmlEscape(ssn);
    String sanitizedSocialSecNum = HtmlUtils.htmlEscape(socialSecurityNum);
    String sanitizedTin = HtmlUtils.htmlEscape(tin);
    String sanitizedPhoneNumber = HtmlUtils.htmlEscape(phoneNumber);

    // empty for now, because we debug
    Set<Account> accounts1 = new HashSet<Account>();
    //dateofbirth example -> "1982-01-10"
    Customer customer1;
    
    try {
        customer1 = new Customer(sanitizedCustomerId, clientId, sanitizedFirstName, sanitizedLastName, 
                              java.sql.Date.valueOf(LocalDate.parse(dateOfBirth)),
                              sanitizedSSN, sanitizedSocialSecNum, sanitizedTin, sanitizedPhoneNumber, 
                              new Address("Debug str", "", "Debug city", "CA", "12345"),
                              accounts1);
    } catch (IllegalArgumentException e) {
        return new ResponseEntity<>("Invalid date format", HttpStatus.BAD_REQUEST);
    }

    customerRepository.save(customer1);
    
    // Set appropriate headers for the response
    httpResponse.setHeader("Location", String.format("%s/customers/%s",
                         request.getContextPath(), customer1.getId()));
                         
    // Add Content Security Policy header
    httpResponse.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'");
    
    // Return DTO instead of domain object using ResponseEntity
    CustomerDTO customerDTO = CustomerDTO.fromCustomer(customer1);
    
    return new ResponseEntity<>(customerDTO, HttpStatus.CREATED);
}

/**
 * Validates input to prevent injection attacks
 * @param input String to validate
 * @return boolean indicating if input is valid
 */
private boolean validateInput(String input) {
    if (input == null || input.trim().isEmpty()) {
        return false;
    }
    return INPUT_PATTERN.matcher(input).matches();
}

    if (success) {
      // Log successful operation
      logger.info(Logger.EVENT_SUCCESS, "Settings successfully saved for resource: {0}", resourceId);
      httpResponse.getOutputStream().println("Settings Saved");
    } else {
      httpResponse.getOutputStream().println("Error: Could not save settings");
      logger.error(Logger.SECURITY_FAILURE, "Failed to save settings for resource: {0}", resourceId);
      throw new Exception("Failed to save settings");
    }
    
  } catch (SecurityException se) {
    // Rethrow security exceptions
    logger.error(Logger.SECURITY_FAILURE, "Security exception in saveSettings: {0}", se.getMessage());
    throw se;
  } catch (Exception e) {
    // Log general exceptions
    logger.error(Logger.SECURITY_FAILURE, "Exception in saveSettings: {0}", e.getMessage());
    throw new Exception("Error processing request");
  }
}

/**
 * Interface for the Storage Service
 * This would be implemented by a concrete class elsewhere
 */
public interface StorageService {
  /**
   * Saves a file securely in the designated location
   * 
   * @param directory The base directory for the file type
   * @param filename The generated unique filename
   * @param content The content to save
   * @return true if save was successful, false otherwise
   */
  boolean saveFile(String directory, String filename, String content);
}

  /**
   * Debug test for saving and reading a customer
   *
   * @param firstName String
   * @param lastName String
   * @param dateOfBirth String
   * @param ssn String
   * @param tin String
   * @param phoneNumber String
   * @param httpResponse
   * @param request
   * @return String
   * @throws IOException
   */
  @RequestMapping(value = "/debug", method = RequestMethod.GET)
  public String debug(@RequestParam String customerId,
					  @RequestParam int clientId,
					  @RequestParam String firstName,
                      @RequestParam String lastName,
                      @RequestParam String dateOfBirth,
                      @RequestParam String ssn,
					  @RequestParam String socialSecurityNum,
                      @RequestParam String tin,
                      @RequestParam String phoneNumber,
                      HttpServletResponse httpResponse,
                     WebRequest request) throws IOException{

    // empty for now, because we debug
    Set<Account> accounts1 = new HashSet<Account>();
    //dateofbirth example -> "1982-01-10"
    Customer customer1 = new Customer(customerId, clientId, firstName, lastName, DateTime.parse(dateOfBirth).toDate(),
                                      ssn, socialSecurityNum, tin, phoneNumber, new Address("Debug str",
                                      "", "Debug city", "CA", "12345"),
                                      accounts1);

    customerRepository.save(customer1);
    httpResponse.setStatus(HttpStatus.CREATED.value());
    httpResponse.setHeader("Location", String.format("%s/customers/%s",
                           request.getContextPath(), customer1.getId()));

    return customer1.toString().toLowerCase().replace("script","");
  }

	/**
	 * Debug test for saving and reading a customer
	 *
	 * @param firstName String
	 * @param httpResponse
	 * @param request
	 * @return void
	 * @throws IOException
	 */
	@RequestMapping(value = "/debugEscaped", method = RequestMethod.GET)
	public void debugEscaped(@RequestParam String firstName, HttpServletResponse httpResponse,
					  WebRequest request) throws IOException{
		String escaped = HtmlUtils.htmlEscape(firstName);
		System.out.println(escaped);
		httpResponse.getOutputStream().println(escaped);
	}
	/**
	 * Gets all customers.
	 *
	 * @return the customers
	 */
	@RequestMapping(value = "/customers", method = RequestMethod.GET)
	public List<Customer> getCustomers() {
		return (List<Customer>) customerRepository.findAll();
	}

	/**
	 * Create a new customer and return in response with HTTP 201
	 *
	 * @param the
	 *            customer
	 * @return created customer
	 */
	@RequestMapping(value = { "/customers" }, method = { RequestMethod.POST })
	public Customer createCustomer(@RequestParam Customer customer, HttpServletResponse httpResponse,
								   WebRequest request) {

		Customer createdcustomer = null;
		createdcustomer = customerRepository.save(customer);
		httpResponse.setStatus(HttpStatus.CREATED.value());
		httpResponse.setHeader("Location",
				String.format("%s/customers/%s", request.getContextPath(), customer.getId()));

		return createdcustomer;
	}

	/**
	 * Update customer with given customer id.
	 *
	 * @param customer
	 *            the customer
	 */
	@RequestMapping(value = { "/customers/{customerId}" }, method = { RequestMethod.PUT })
	public void updateCustomer(@RequestBody Customer customer, @PathVariable("customerId") Long customerId,
			HttpServletResponse httpResponse) {

		if (!customerRepository.exists(customerId)) {
			httpResponse.setStatus(HttpStatus.NOT_FOUND.value());
		} else {
			customerRepository.save(customer);
			httpResponse.setStatus(HttpStatus.NO_CONTENT.value());
		}
	}

	/**
	 * Deletes the customer with given customer id if it exists and returns
	 * HTTP204.
	 *
	 * @param customerId
	 *            the customer id
	 */
	@RequestMapping(value = "/customers/{customerId}", method = RequestMethod.DELETE)
	public void removeCustomer(@PathVariable("customerId") Long customerId, HttpServletResponse httpResponse) {

		if (customerRepository.exists(customerId)) {
			customerRepository.delete(customerId);
		}

		httpResponse.setStatus(HttpStatus.NO_CONTENT.value());
	}

}
