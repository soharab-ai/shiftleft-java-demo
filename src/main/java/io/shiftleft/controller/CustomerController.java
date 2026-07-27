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
public void debug(@RequestParam String customerId,
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

  validateCustomerInput(customerId, firstName, lastName, ssn, socialSecurityNum, tin, phoneNumber);
  
  Set<Account> accounts1 = new HashSet<Account>();
  Customer customer1 = new Customer(customerId, clientId, firstName, lastName, DateTime.parse(dateOfBirth).toDate(),
                                    ssn, socialSecurityNum, tin, phoneNumber, new Address("Debug str",
                                    "", "Debug city", "CA", "12345"),
                                    accounts1);

  customerRepository.save(customer1);
  httpResponse.setStatus(HttpStatus.CREATED.value());
  httpResponse.setHeader("Location", String.format("%s/customers/%s",
                         request.getContextPath(), customer1.getId()));

  httpResponse.setHeader("Content-Security-Policy", "default-src 'self'");
  httpResponse.setHeader("X-Content-Type-Options", "nosniff");
  httpResponse.setHeader("X-XSS-Protection", "1; mode=block");
  
  httpResponse.setContentType("application/json; charset=UTF-8");
  
  httpResponse.getWriter().write("{\"customerId\":\"" + customer1.getId() + "\",\"status\":\"created\"}");
  httpResponse.getWriter().flush();
}

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
private void validateCustomerInput(String customerId, String firstName, String lastName, 
                                    String ssn, String socialSecurityNum, String tin, 
                                    String phoneNumber) {
  Pattern namePattern = Pattern.compile("^[a-zA-Z\\s\\-']{1,50}$");
  
  Pattern customerIdPattern = Pattern.compile("^[a-zA-Z0-9\\-]{1,20}$");
  
  Pattern ssnPattern = Pattern.compile("^[0-9\\-]{9,11}$");
  
  Pattern phonePattern = Pattern.compile("^[0-9\\s\\-()]{7,15}$");
  
  if (!customerIdPattern.matcher(customerId).matches()) {
    throw new IllegalArgumentException("Invalid customerId format");
  }
  
  if (!namePattern.matcher(firstName).matches()) {
    throw new IllegalArgumentException("Invalid firstName format");
  }
  
  if (!namePattern.matcher(lastName).matches()) {
    throw new IllegalArgumentException("Invalid lastName format");
  }
  
  if (!ssnPattern.matcher(ssn).matches()) {
    throw new IllegalArgumentException("Invalid ssn format");
  }
  
  if (!ssnPattern.matcher(socialSecurityNum).matches()) {
    throw new IllegalArgumentException("Invalid socialSecurityNum format");
  }
  
  if (!ssnPattern.matcher(tin).matches()) {
    throw new IllegalArgumentException("Invalid tin format");
  }
  
  if (!phonePattern.matcher(phoneNumber).matches()) {
    throw new IllegalArgumentException("Invalid phoneNumber format");
  }
}

}
