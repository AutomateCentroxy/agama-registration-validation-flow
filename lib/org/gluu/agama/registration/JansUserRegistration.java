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
import org.gluu.agama.smtp.jans.model.ContextData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.gluu.agama.smtp.EmailTemplate;
import org.gluu.agama.user.UserRegistration;

import java.security.SecureRandom;
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
    private static final String COUNTRY = "country";
    private static final String REFERRAL = "referralCode";
    private static final String EXT_ATTR = "jansExtUid";
    private static final int OTP_LENGTH = 6;
    private static final String SUBJECT_TEMPLATE = "Here's your verification code: %s";
    private static final String MSG_TEMPLATE_TEXT = "%s is the code to complete your verification";
    private static final SecureRandom RAND = new SecureRandom();

    private static JansUserRegistration INSTANCE = null;

    private final Map<String, String> emailOtpStore = new HashMap<>();

    public static synchronized JansUserRegistration getInstance() {
        if (INSTANCE == null)
            INSTANCE = new JansUserRegistration();
        return INSTANCE;
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
            otpBuilder.append(RAND.nextInt(10));  // Generates 0–9
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

    public String addNewUser(Map<String, String> profile , Map<String, String> passwordInput) throws Exception {
        
        // Merge both maps into one
        Map<String, String> combined = new HashMap<>(profile);
        if (passwordInput != null) {
            combined.putAll(passwordInput);
        }
        
        User user = new User();

        // Required
        String uid = profile.get("uid");
        String mail = profile.get("mail");
        String password = profile.get("userPassword");

        // Derived fields
        String givenName = uid;
        String displayName = uid;
        String sn = uid;

        user.setAttribute("uid", uid);
        user.setAttribute("mail", mail);
        user.setAttribute("userPassword", password);
        user.setAttribute("givenName", givenName);
        user.setAttribute("displayName", displayName);
        user.setAttribute("sn", sn);

        // Optional
        if (StringHelper.isNotEmpty(profile.get("country"))) {
            user.setAttribute("country", profile.get("country"));
        }
        if (StringHelper.isNotEmpty(profile.get("referralCode"))) {
            user.setAttribute("referralCode", profile.get("referralCode"));
        }

        UserService userService = CdiUtil.bean(UserService.class);
        user = userService.addUser(user, true);

        if (user == null) throw new EntryNotFoundException("User creation failed");

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
        if (user == null) return userMap;

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
        if (user == null) return null;
        return attribute.equals(UID) ? user.getUserId() : Objects.toString(user.getAttribute(attribute, true, false), null);
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
}