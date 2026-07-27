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
   */
@RequestMapping(value = "/debug", method = RequestMethod.GET)
public String debug(@Valid CustomerDebugDTO debugDTO,
                   BindingResult bindingResult,
                   HttpServletResponse httpResponse,
                   WebRequest request) throws IOException {

  if (bindingResult.hasErrors()) {
      httpResponse.setStatus(HttpStatus.BAD_REQUEST.value());
      String errorMessages = bindingResult.getAllErrors().stream()
          .map(error -> Encode.forHtml(error.getDefaultMessage()))
          .collect(Collectors.joining("; "));
      return errorMessages;
  }

  httpResponse.setHeader("Content-Security-Policy", 
      "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
  
  httpResponse.setHeader("X-Content-Type-Options", "nosniff");
  httpResponse.setHeader("X-Frame-Options", "DENY");
  httpResponse.setHeader("X-XSS-Protection", "1; mode=block");

  Date parsedDate;
  try {
      LocalDate localDate = LocalDate.parse(debugDTO.getDateOfBirth(), DateTimeFormatter.ISO_LOCAL_DATE);
      parsedDate = Date.valueOf(localDate);
  } catch (DateTimeParseException e) {
      httpResponse.setStatus(HttpStatus.BAD_REQUEST.value());
      return Encode.forHtml("Invalid date format for dateOfBirth");
  }

  Set<Account> accounts1 = new HashSet<Account>();
  Customer customer1 = new Customer(debugDTO.getCustomerId(), debugDTO.getClientId(), 
                                    debugDTO.getFirstName(), debugDTO.getLastName(), parsedDate,
                                    debugDTO.getSsn(), debugDTO.getSocialSecurityNum(), 
                                    debugDTO.getTin(), debugDTO.getPhoneNumber(), 
                                    new Address("Debug str", "", "Debug city", "CA", "12345"),
                                    accounts1);

  Customer sanitizedCustomer = sanitizeCustomerForStorage(customer1);
  customerRepository.save(sanitizedCustomer);
  
  httpResponse.setStatus(HttpStatus.CREATED.value());
  httpResponse.setHeader("Location", String.format("%s/customers/%s",
                         request.getContextPath(), sanitizedCustomer.getId()));

  httpResponse.setContentType("application/json");
  Map<String, String> response = new HashMap<>();
  response.put("id", Encode.forHtml(sanitizedCustomer.getId()));
  response.put("customerId", Encode.forHtml(sanitizedCustomer.getCustomerId()));
  response.put("status", "Customer created successfully");

  ObjectMapper mapper = new ObjectMapper();
  return mapper.writeValueAsString(response);
}

	@RequestMapping(value = { "/customers" }, method = { RequestMethod.POST })
	public Customer createCustomer(@RequestParam Customer customer, HttpServletResponse httpResponse,
								   WebRequest request) {

		Customer createdcustomer = null;
		createdcustomer = customerRepository.save(customer);
		httpResponse.setStatus(HttpStatus.CREATED.value());
private Customer sanitizeCustomerForStorage(Customer customer) {
  customer.setFirstName(Encode.forHtmlContent(customer.getFirstName()));
  customer.setLastName(Encode.forHtmlContent(customer.getLastName()));
  customer.setCustomerId(Encode.forHtmlContent(customer.getCustomerId()));
  customer.setPhoneNumber(Encode.forHtmlContent(customer.getPhoneNumber()));
  customer.setSsn(Encode.forHtmlContent(customer.getSsn()));
  customer.setSocialSecurityNum(Encode.forHtmlContent(customer.getSocialSecurityNum()));
  customer.setTin(Encode.forHtmlContent(customer.getTin()));
  return customer;
}

  private int clientId;
  
  @NotBlank(message = "First name is required")
  @Pattern(regexp = "^[a-zA-Z\\s'\\-]{1,50}$", message = "Invalid firstName format. Only letters, spaces, hyphens, and apostrophes allowed, max 50 characters.")
  private String firstName;
  
  @NotBlank(message = "Last name is required")
  @Pattern(regexp = "^[a-zA-Z\\s'\\-]{1,50}$", message = "Invalid lastName format. Only letters, spaces, hyphens, and apostrophes allowed, max 50 characters.")
  private String lastName;
  
  @NotBlank(message = "Date of birth is required")
  @Pattern(regexp = "^\\d{4}-\\d{2}-\\d{2}$", message = "Invalid date format, use YYYY-MM-DD")
  private String dateOfBirth;
  
  @NotBlank(message = "SSN is required")
  @Pattern(regexp = "^\\d{3}-\\d{2}-\\d{4}$", message = "Invalid SSN format. Expected format: XXX-XX-XXXX.")
  private String ssn;
  
  @NotBlank(message = "Social Security Number is required")
  @Pattern(regexp = "^\\d{9}$", message = "Invalid socialSecurityNum format. Expected 9 digits.")
  private String socialSecurityNum;
  
  @NotBlank(message = "TIN is required")
  @Pattern(regexp = "^\\d{2}-\\d{7}$", message = "Invalid TIN format. Expected format: XX-XXXXXXX.")
  private String tin;
  
  @NotBlank(message = "Phone number is required")
  @Pattern(regexp = "^[0-9\\s\\-\\(\\)]{1,20}$", message = "Invalid phoneNumber format. Only digits, spaces, hyphens, parentheses allowed, max 20 characters.")
  private String phoneNumber;

  public String getCustomerId() {
      return customerId;
  }

  public void setCustomerId(String customerId) {
      this.customerId = customerId;
  }

  public int getClientId() {
      return clientId;
  }

  public void setClientId(int clientId) {
      this.clientId = clientId;
  }

  public String getFirstName() {
      return firstName;
  }

  public void setFirstName(String firstName) {
      this.firstName = firstName;
  }

  public String getLastName() {
      return lastName;
  }

  public void setLastName(String lastName) {
      this.lastName = lastName;
  }

  public String getDateOfBirth() {
      return dateOfBirth;
  }

  public void setDateOfBirth(String dateOfBirth) {
      this.dateOfBirth = dateOfBirth;
  }

  public String getSsn() {
      return ssn;
  }

  public void setSsn(String ssn) {
      this.ssn = ssn;
  }

  public String getSocialSecurityNum() {
      return socialSecurityNum;
  }

  public void setSocialSecurityNum(String socialSecurityNum) {
      this.socialSecurityNum = socialSecurityNum;
  }

  public String getTin() {
      return tin;
  }

  public void setTin(String tin) {
      this.tin = tin;
  }

  public String getPhoneNumber() {
      return phoneNumber;
  }

  public void setPhoneNumber(String phoneNumber) {
      this.phoneNumber = phoneNumber;
  }
}
