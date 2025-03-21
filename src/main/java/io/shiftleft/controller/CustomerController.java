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
  public void saveSettings(HttpServletResponse httpResponse, WebRequest request) throws Exception {
    // "Settings" will be stored in a cookie
    // schema: base64(filename,value1,value2...), md5sum(base64(filename,value1,value2...))

    if (!checkCookie(request)){
      httpResponse.getOutputStream().println("Error");
      throw new Exception("cookie is incorrect");
    }

    String settingsCookie = request.getHeader("Cookie");
    String[] cookie = settingsCookie.split(",");
	if(cookie.length<2) {
	  httpResponse.getOutputStream().println("Malformed cookie");
      throw new Exception("cookie is incorrect");
    }

    String base64txt = cookie[0].replace("settings=","");

    // Check md5sum
    String cookieMD5sum = cookie[1];
    String calcMD5Sum = DigestUtils.md5Hex(base64txt);
	if(!cookieMD5sum.equals(calcMD5Sum))
    {
      httpResponse.getOutputStream().println("Wrong md5");
      throw new Exception("Invalid MD5");
    }

    // Now we can store on filesystem
    String[] settings = new String(Base64.getDecoder().decode(base64txt)).split(",");
	// storage will have ClassPathResource as basepath
    ClassPathResource cpr = new ClassPathResource("./static/");
	  File file = new File(cpr.getPath()+settings[0]);
    if(!file.exists()) {
      file.getParentFile().mkdirs();
    }

    FileOutputStream fos = new FileOutputStream(file, true);
    // First entry is the filename -> remove it
    String[] settingsArr = Arrays.copyOfRange(settings, 1, settings.length);
    // on setting at a linez
    fos.write(String.join("\n",settingsArr).getBytes());
    fos.write(("\n"+cookie[cookie.length-1]).getBytes());
    fos.close();
    httpResponse.getOutputStream().println("Settings Saved");
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
/**
 * Debug endpoint for customer data - restricted to dev environment and admin users only
 */
@Profile("dev") // Added profile restriction for development environment only
@PreAuthorize("hasRole('ADMIN')") // Added role-based access control
@RequestMapping(value = "/debug", method = RequestMethod.GET)
public ResponseEntity<CustomerResponseDTO> debug(@Valid @RequestBody CustomerRequestDTO customerRequest,
                                               HttpServletResponse httpResponse,
                                               WebRequest request) throws IOException {
    try {
        // Using DTO with Bean Validation instead of individual parameters
        // All validation is now handled by JSR 380 annotations in the DTO
        
        Set<Account> accounts = new HashSet<>();
        Customer customer = new Customer(
            customerRequest.getCustomerId(),
            customerRequest.getClientId(),
            customerRequest.getFirstName(),
            customerRequest.getLastName(),
            LocalDate.parse(customerRequest.getDateOfBirth()).atStartOfDay(java.time.ZoneId.systemDefault()).toInstant().toDate(),
            customerRequest.getSsn(),
            customerRequest.getSocialSecurityNum(),
            customerRequest.getTin(),
            customerRequest.getPhoneNumber(),
            new Address(
                customerRequest.getStreet(),
                customerRequest.getStreet2(),
                customerRequest.getCity(),
                customerRequest.getState(),
                customerRequest.getZipCode()
            ),
            accounts
        );

        customerRepository.save(customer);
        
        // Set security headers
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(String.format("%s/customers/%s", request.getContextPath(), customer.getId())));
        
        // Enhanced Content Security Policy with more restrictive directives
        headers.set(HttpHeaders.CONTENT_SECURITY_POLICY, 
                "default-src 'self'; script-src 'self'; object-src 'none'; " +
                "style-src 'self'; img-src 'self'; font-src 'self'; " +
                "form-action 'self'; frame-ancestors 'none'; base-uri 'self'");
        
        // Added X-Content-Type-Options header to prevent MIME type sniffing
        headers.set("X-Content-Type-Options", "nosniff");
        
        // Added X-Frame-Options header to prevent clickjacking
        headers.set("X-Frame-Options", "DENY");
        
        // Create response DTO that only includes non-sensitive data
        CustomerResponseDTO responseDTO = new CustomerResponseDTO(
            customer.getId(),
            customer.getFirstName(),
            customer.getLastName(),
            // Masking sensitive data in the response
            maskSensitiveData(customer.getPhoneNumber())
        );
        
        // Return ResponseEntity with proper status code, headers and body
        return new ResponseEntity<>(responseDTO, headers, HttpStatus.CREATED);
    } catch (Exception e) {
        // Logging the error without exposing implementation details
        logger.error("Error processing customer debug request: null", e.getMessage());
        
        // Throwing a custom exception that will be handled by global exception handler
        throw new CustomerProcessingException("Unable to process customer data");
    }
}

/**
 * Request DTO with validation annotations
 */
@Validated
public static class CustomerRequestDTO {
    @NotBlank
    @Pattern(regexp = "^[a-zA-Z0-9-_]{1,36}$", message = "Invalid customer ID format")
    private String customerId;
    
    @NotNull
    @Min(1)
    private Integer clientId;
    
    @NotBlank
    @Pattern(regexp = "^[a-zA-Z\\s-']{2,50}$", message = "Invalid first name format")
    private String firstName;
    
    @NotBlank
    @Pattern(regexp = "^[a-zA-Z\\s-']{2,50}$", message = "Invalid last name format")
    private String lastName;
    
    @NotBlank
    @Pattern(regexp = "^\\d{4}-\\d{2}-\\d{2}$", message = "Date of birth must be in yyyy-MM-dd format")
    private String dateOfBirth;
    
    @Pattern(regexp = "^\\d{3}-\\d{2}-\\d{4}$", message = "SSN must be in XXX-XX-XXXX format")
    private String ssn;
    
    @Pattern(regexp = "^\\d{3}-\\d{2}-\\d{4}$", message = "Social security number must be in XXX-XX-XXXX format")
    private String socialSecurityNum;
    
    @Pattern(regexp = "^\\d{2}-\\d{7}$", message = "TIN must be in XX-XXXXXXX format")
    private String tin;
    
    @Pattern(regexp = "^\\d{3}-\\d{3}-\\d{4}$", message = "Phone number must be in XXX-XXX-XXXX format")
    private String phoneNumber;
    
    @NotBlank
    @Length(max = 100)
    private String street;
    
    @Length(max = 100)
    private String street2;
    
    @NotBlank
    @Length(max = 50)
    @Pattern(regexp = "^[a-zA-Z\\s-']{2,50}$", message = "Invalid city format")
    private String city;
    
    @NotBlank
    @Length(min = 2, max = 2)
    @Pattern(regexp = "^[A-Z]{2}$", message = "State must be a two-letter code")
    private String state;
    
    @NotBlank
    @Pattern(regexp = "^\\d{5}(-\\d{4})?$", message = "Zip code must be in XXXXX or XXXXX-XXXX format")
    private String zipCode;
    
    // Getters and setters omitted for brevity
    // ... add all getters and setters for the fields
}

/**
 * Response DTO that only includes non-sensitive data
 */
public static class CustomerResponseDTO {
    private final String id;
    private final String firstName;
    private final String lastName;
    private final String maskedPhoneNumber;
    
    public CustomerResponseDTO(String id, String firstName, String lastName, String maskedPhoneNumber) {
        this.id = id;
        this.firstName = firstName;
        this.lastName = lastName;
        this.maskedPhoneNumber = maskedPhoneNumber;
    }
    
    // Getters omitted for brevity
    // ... add all getters for the fields
}

/**
 * Mask sensitive data like phone numbers
 */
private String maskSensitiveData(String phoneNumber) {
    if (phoneNumber == null || phoneNumber.length() < 8) {
        return "XXX-XXX-XXXX";
    }
    
    // Only show the last 4 digits
    return "XXX-XXX-" + phoneNumber.substring(phoneNumber.length() - 4);
}

/**
 * Custom exception for customer processing errors
 */
public class CustomerProcessingException extends RuntimeException {
    public CustomerProcessingException(String message) {
        super(message);
    }
}

/**
 * Global exception handler to avoid exposing implementation details
 */
@ControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(CustomerProcessingException.class)
    public ResponseEntity<ErrorResponse> handleCustomerProcessingException(CustomerProcessingException ex) {
        ErrorResponse error = new ErrorResponse("Unable to process customer data");
        return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationExceptions(MethodArgumentNotValidException ex) {
        ErrorResponse error = new ErrorResponse("Invalid input data");
        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }
    
    // Additional exception handlers as needed
}

/**
 * Error response DTO
 */
public class ErrorResponse {
    private final String message;
    
    public ErrorResponse(String message) {
        this.message = message;
    }
    
    public String getMessage() {
        return message;
    }
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
