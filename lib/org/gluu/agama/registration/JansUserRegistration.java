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
import java.util.stream.IntStream;

import static org.gluu.agama.registration.jans.Attrs.*;

public class JansUserRegistration extends UserRegistration {

    private static final String MAIL = "mail";
    private static final String UID = "uid";
    private static final String DISPLAY_NAME = "displayName";
    private static final String GIVEN_NAME = "givenName";
    private static final String PASSWORD = "userPassword";
    private static final String INUM_ATTR = "inum";
    private static final String USER_STATUS = "jansStatus";
    private static final String PHONE = "jansMobile";
    private static final String COUNTRY = "residenceCountry";
    private static final String REFERRAL = "referralCode";
    private static final String EXT_ATTR = "jansExtUid";
    private static final int OTP_LENGTH = 6;

    private static final SecureRandom RAND = new SecureRandom();
    private static JansUserRegistration INSTANCE = null;

    private final Map<String, String> smsOtpStore = new HashMap<>();
    private final Map<String, String> emailOtpStore = new HashMap<>();

    public static synchronized JansUserRegistration getInstance() {
        if (INSTANCE == null)
            INSTANCE = new JansUserRegistration();
        return INSTANCE;
    }

    public boolean passwordPolicyMatch(String userPassword) {
        String regex = "^(?=.*[!@#$^&*])[A-Za-z0-9!@#$^&*]{6,}$";
        return Pattern.compile(regex).matcher(userPassword).matches();
    }

    public boolean usernamePolicyMatch(String userName) {
        return Pattern.compile("^[A-Za-z]+$").matcher(userName).matches();
    }

    public boolean checkIfUserExists(String username, String email) {
        return !getUserEntityByUsername(username).isEmpty() || !getUserEntityByMail(email).isEmpty();
    }

    public boolean matchPasswords(String pwd1, String pwd2) {
        return pwd1 != null && pwd1.equals(pwd2);
    }

    public boolean sendSmsOtp(String phoneNumber, Map<String, String> conf) {
        try {
            LogUtils.log("Sending OTP Code via SMS to %.", phoneNumber);
            String otpCode = generateOtpCode(OTP_LENGTH);
            String message = "Hi, your OTP Code to complete your registration is: " + otpCode;
            associateOtpWithPhone(phoneNumber, otpCode);

            String ACCOUNT_SID = conf.get("ACCOUNT_SID");
            String AUTH_TOKEN = conf.get("AUTH_TOKEN");
            String FROM_NUMBER = conf.get("FROM_NUMBER");

            com.twilio.Twilio.init(ACCOUNT_SID, AUTH_TOKEN);
            com.twilio.rest.api.v2010.account.Message.creator(
                new com.twilio.type.PhoneNumber(phoneNumber),
                new com.twilio.type.PhoneNumber(FROM_NUMBER),
                message
            ).create();

            return true;
        } catch (Exception e) {
            LogUtils.log("Failed to send SMS to %: %", phoneNumber, e.getMessage());
            return false;
        }
    }

    public boolean validateSmsOtp(String phoneNumber, String code) {
        String storedCode = smsOtpStore.getOrDefault(phoneNumber, "NULL");
        if (storedCode.equalsIgnoreCase(code)) {
            smsOtpStore.remove(phoneNumber);
            return true;
        }
        return false;
    }

    public boolean sendEmailOtp(String email) {
        try {
            ContextData context = new ContextData();
            String otp = generateOtpCode(OTP_LENGTH);
            SmtpConfiguration smtpConfiguration = getSmtpConfiguration();

            String from = smtpConfiguration.getFromEmailAddress();
            String subject = String.format("Here's your verification code: %s", otp);
            String textBody = String.format("%s is the code to complete your verification", otp);
            String htmlBody = EmailTemplate.get(otp, context);

            MailService mailService = CdiUtil.bean(MailService.class);
            boolean sent = mailService.sendMailSigned(from, from, email, null, subject, textBody, htmlBody);

            if (sent) {
                emailOtpStore.put(email, otp);
                return true;
            }

            return false;
        } catch (Exception e) {
            LogUtils.log("Error sending email OTP to %: %", email, e.getMessage());
            return false;
        }
    }

    public boolean validateEmailOtp(String email, String otp) {
        String sentOtp = emailOtpStore.get(email);
        return otp != null && otp.equals(sentOtp);
    }

    public String addNewUser(Map<String, String> profile) throws Exception {
        Set<String> attributes = Set.of("uid", "mail", "displayName", "givenName", "sn", "userPassword", PHONE, COUNTRY, REFERRAL);
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

    private void associateOtpWithPhone(String phone, String otp) {
        smsOtpStore.put(phone, otp);
    }

    private SmtpConfiguration getSmtpConfiguration() {
        return CdiUtil.bean(ConfigurationService.class).getConfiguration().getSmtpConfiguration();
    }
}
