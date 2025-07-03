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

import org.gluu.agama.registration.jans.model.ContextData;
import org.gluu.agama.smtp.EmailTemplate;
import org.gluu.agama.user.UserRegistration;

import java.security.SecureRandom;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.gluu.agama.registration.jans.Attrs.*;

public class JansUserRegistration extends UserRegistration {

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

    public String sendEmail(String to, ContextData context) {

        SmtpConfiguration smtpConfiguration = getSmtpConfiguration();
        IntStream digits = RAND.ints(OTP_LENGTH, 0, 10);
        String otp = digits.mapToObj(i -> "" + i).collect(Collectors.joining());

        String from = smtpConfiguration.getFromEmailAddress();
        String subject = String.format(SUBJECT_TEMPLATE, otp);
        String textBody = String.format(MSG_TEMPLATE_TEXT, otp);
        String htmlBody = EmailTemplate.get(otp, context);

        MailService mailService = CdiUtil.bean(MailService.class);

        if (mailService.sendMailSigned(from, from, to, null, subject, textBody, htmlBody)) {
            logger.debug("E-mail has been delivered to {} with code {}", to, otp);
            return otp;
        }
        logger.debug("E-mail delivery failed, check jans-auth logs");
        return null;

    }

    public String addNewUser(Map<String, String> profile) throws Exception {
        Set<String> attributes = Set.of("uid", "mail", "displayName", "givenName", "sn", "userPassword", COUNTRY, REFERRAL);
        User user = new User();

        attributes.forEach(attr -> {
            String val = profile.get(attr);
            if (StringHelper.isNotEmpty(val)) {
                user.setAttribute(attr, val);
            }
        });

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
