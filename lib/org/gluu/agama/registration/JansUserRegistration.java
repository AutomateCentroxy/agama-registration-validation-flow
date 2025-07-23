package org.gluu.agama.registration;
 
import io.jans.as.common.model.common.User;
import io.jans.as.common.service.common.ConfigurationService;
import io.jans.as.common.service.common.UserService;
import io.jans.model.SmtpConfiguration;
import io.jans.orm.exception.operation.EntryNotFoundException;
import io.jans.service.MailService;
import io.jans.service.cdi.util.CdiUtil;
import io.jans.util.StringHelper;
import io.jans.agama.engine.script.LogUtils;
import io.jans.as.common.service.common.EncryptionService;
import io.jans.util.security.StringEncrypter;
import org.gluu.agama.smtp.jans.model.ContextData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
 
import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
 
import org.gluu.agama.smtp.EmailTemplate;
import org.gluu.agama.user.UserRegistration;
 
import java.security.SecureRandom;
// Utility
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
 
import static org.gluu.agama.registration.jans.Attrs.*;
 
public class JansUserRegistration extends UserRegistration {
 
    private static final Logger logger = LoggerFactory.getLogger(JansUserRegistration.class);
 
    private static final String MAIL = "mail";
    private static final String UID = "uid";
    private static final String DISPLAY_NAME = "displayName";
    private static final String GIVEN_NAME = "givenName";
    private static final String PASSWORD = "userPassword";
    private static final String INUM_ATTR = "inum";
    private static final String USER_STATUS = "jansStatus";
    private static final String COUNTRY = "residenceCountry";
    private static final String REFERRAL = "referralCode";
    private static final String EXT_ATTR = "jansExtUid";
    private static final int OTP_LENGTH = 6;
    public static final int OTP_CODE_LENGTH = 6;
    private static final String SUBJECT_TEMPLATE = "Here's your verification code: %s";
    private static final String MSG_TEMPLATE_TEXT = "%s is the code to complete your verification";
    private static final SecureRandom RAND = new SecureRandom();
    private final Map<String, String> flowConfig;
    private static JansUserRegistration INSTANCE = null;
   
    private final Map<String, String> emailOtpStore = new HashMap<>();
     
    //private HashMap<String, String> userCodes = new HashMap<>();
    private static final Map<String, String> userCodes = new HashMap<>();
 
    public JansUserRegistration() {
        this.flowConfig = new HashMap<>();
    }
 
    // Required by your `UserRegistration.getInstance(config)` call
    public JansUserRegistration(Map config) {
        this.flowConfig = config;
        logger.info("Using Twilio account SID: {}", config.get("ACCOUNT_SID"));
    }
 
 
    public boolean passwordPolicyMatch(String userPassword) {
        String regex = '''^(?=.*[!@#$^&*])[A-Za-z0-9!@#$^&*]{6,}$''';
        return Pattern.compile(regex).matcher(userPassword).matches();
    }
 
    public boolean usernamePolicyMatch(String userName) {
        String regex = '''^[A-Za-z]+$''';
        return Pattern.compile(regex).matcher(userName).matches();
    }
 
    public boolean checkIfUserExists(String username, String email) {
        return !getUserEntityByUsername(username).isEmpty() || !getUserEntityByMail(email).isEmpty();
    }
 
    public boolean matchPasswords(String pwd1, String pwd2) {
        return pwd1 != null && pwd1.equals(pwd2);
    }
 
    public String sendEmail(String to) {
 
        SmtpConfiguration smtpConfiguration = getSmtpConfiguration();
 
        StringBuilder otpBuilder = new StringBuilder();
        for (int i = 0; i < OTP_LENGTH; i++) {
            otpBuilder.append(RAND.nextInt(10)); // Generates 0–9
        }
        String otp = otpBuilder.toString();
 
        String from = smtpConfiguration.getFromEmailAddress();
        String subject = String.format(SUBJECT_TEMPLATE, otp);
        String textBody = String.format(MSG_TEMPLATE_TEXT, otp);
        ContextData context = new ContextData();
        context.setDevice("Unknown");
        context.setTimeZone("Unknown");
        context.setLocation("Unknown");
        String htmlBody = EmailTemplate.get(otp, context);
 
        MailService mailService = CdiUtil.bean(MailService.class);
 
        if (mailService.sendMailSigned(from, from, to, null, subject, textBody, htmlBody)) {
            logger.debug("E-mail has been delivered to {} with code {}", to, otp);
            return otp;
        }
        logger.debug("E-mail delivery failed, check jans-auth logs");
        return null;
 
    }
 
    public String sendOTPCode(String phone) {
        try {
            logger.info("Sending OTP Code via SMS to phone: {}", phone);
 
            String otpCode = generateSMSOTpCode(OTP_CODE_LENGTH);
 
            logger.info("Generated OTP {} for phone {}", otpCode, phone);
 
            String message = "Welcome to AgamaLab. This is your OTP Code: " + otpCode;
            // Store OTP mapped to phone (not username)
            associateGeneratedCodeToPhone(phone, otpCode);
            // You can pass `null` or "anonymous" instead of username
            sendTwilioSms(phone, message);
            return phone; // Return phone if successful
        } catch (Exception ex) {
            logger.error("Failed to send OTP to phone: {}. Error: {}", phone);
            return null;
        }
 
    }
 
    private String generateSMSOTpCode(int codeLength) {
        String numbers = "0123456789";
        SecureRandom random = new SecureRandom();
        char[] otp = new char[codeLength];
        for (int i = 0; i < codeLength; i++) {
            otp[i] = numbers.charAt(random.nextInt(numbers.length()));
        }
        return new String(otp);
    }
 
    private boolean associateGeneratedCodeToPhone(String phone, String code) {
        try {
            userCodes.put(phone, code);
            return true;
        } catch (Exception e) {
            logger.error("Error associating OTP code to phone {}. Error: {}", phone, e.getMessage(), e);
            return false;
        }
    }
 
    public boolean validateOTPCode(String phone, String code) {
        try {
            logger.info("Validating OTP code {} for phone {}", code, phone);
            String storedCode = userCodes.getOrDefault(phone, "NULL");
            if (storedCode.equalsIgnoreCase(code)) {
                userCodes.remove(phone); // Remove after successful validation
                return true;
            }
            return false;
        } catch (Exception ex) {
            logger.error("Error validating OTP code {} for phone {}. Error: {}", code, phone, ex.getMessage(), ex);
            return false;
        }
    }
 
    public String addNewUser(Map<String, String> profile, Map<String, String> passwordInput) throws Exception {
 
        Logger logger = LoggerFactory.getLogger(JansUserRegistration.class);
        logger.info(" Starting user registration...");
 
        Map<String, String> combined = new HashMap<>(profile);
        if (passwordInput != null) {
            combined.putAll(passwordInput);
        }
 
        String uid = combined.get("uid");
        String mail = combined.get("mail");
        String password = combined.get("userPassword");
 
        if (StringHelper.isEmpty(uid) || StringHelper.isEmpty(password)) {
            throw new IllegalArgumentException("UID and password are required.");
        }
 
        User user = new User();
        user.setAttribute("uid", uid);
        user.setAttribute("mail", mail);
        user.setAttribute("displayName", uid);
        user.setAttribute("givenName", uid);
        user.setAttribute("sn", uid);
        user.setAttribute("userPassword", password); // let Jans hash it
 
        if (StringHelper.isNotEmpty(combined.get("residenceCountry"))) {
            user.setAttribute("residenceCountry", combined.get("residenceCountry"));
        }
 
        if (StringHelper.isNotEmpty(combined.get("referralCode"))) {
            user.setAttribute("referralCode", combined.get("referralCode"));
        }
 
        UserService userService = CdiUtil.bean(UserService.class);
        user = userService.addUser(user, true); // status: active
 
        if (user == null) {
            logger.error("Failed to create user.");
            throw new EntryNotFoundException("User creation failed");
        }
 
        logger.info(" User created with UID: {}", uid);
        return getSingleValuedAttr(user, INUM_ATTR);
    }
 
    public Map<String, String> getUserEntityByMail(String email) {
        return extractUserInfo(getUser(MAIL, email), email);
    }
 
    public Map<String, String> getUserEntityByUsername(String username) {
        return extractUserInfo(getUser(UID, username), null);
    }
 
    private Map<String, String> extractUserInfo(User user, String fallbackEmail) {
        Map<String, String> userMap = new HashMap<>();
        if (user == null)
            return userMap;
 
        userMap.put(UID, getSingleValuedAttr(user, UID));
        userMap.put(INUM_ATTR, getSingleValuedAttr(user, INUM_ATTR));
        userMap.put("name", Optional.ofNullable(getSingleValuedAttr(user, GIVEN_NAME))
                .orElseGet(() -> getSingleValuedAttr(user, DISPLAY_NAME)));
        userMap.put("email", Optional.ofNullable(getSingleValuedAttr(user, MAIL)).orElse(fallbackEmail));
        return userMap;
    }
 
    private static User getUser(String attributeName, String value) {
        return CdiUtil.bean(UserService.class).getUserByAttribute(attributeName, value, true);
    }
 
    private String getSingleValuedAttr(User user, String attribute) {
        if (user == null)
            return null;
        return attribute.equals(UID) ? user.getUserId()
                : Objects.toString(user.getAttribute(attribute, true, false), null);
    }
 
    private String generateOtpCode(int length) {
        return RAND.ints(length, 0, 10).mapToObj(String::valueOf).collect(Collectors.joining());
    }
 
    // Implementing this to satisfy abstract class requirement
    private SmtpConfiguration getSmtpConfiguration() {
        ConfigurationService configurationService = CdiUtil.bean(ConfigurationService.class);
        SmtpConfiguration smtpConfiguration = configurationService.getConfiguration().getSmtpConfiguration();
        return smtpConfiguration;
 
    }
 
    private boolean sendTwilioSms(String phone, String message) {
        try {
 
            PhoneNumber FROM_NUMBER = new com.twilio.type.PhoneNumber(flowConfig.get("FROM_NUMBER"));
 
            logger.info("FROM_NUMBER", FROM_NUMBER);
 
            PhoneNumber TO_NUMBER = new com.twilio.type.PhoneNumber(phone);
 
            logger.info("TO_NUMBER", TO_NUMBER);
 
            Twilio.init(flowConfig.get("ACCOUNT_SID"), flowConfig.get("AUTH_TOKEN"));
 
            logger.info(null, flowConfig.get("ACCOUNT_SID"), flowConfig.get("AUTH_TOKEN"));
 
            Message.creator(TO_NUMBER, FROM_NUMBER, message).create();
 
            logger.info("OTP code has been successfully send to {} on phone number {} .", phone);
 
            return true;
        } catch (Exception exception) {
            logger.error("Error sending OTP code to user {} on pone number {} : error {} .", phone,
                    exception.getMessage(), exception);
            return false;
        }
    }
 
}