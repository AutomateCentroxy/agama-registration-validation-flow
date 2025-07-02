package org.gluu.agama.registration;

import io.jans.as.common.model.common.User;
import io.jans.as.common.service.common.UserService;
import io.jans.orm.exception.operation.EntryNotFoundException;
import io.jans.service.cdi.util.CdiUtil;
import io.jans.util.StringHelper;
import org.gluu.agama.registration.jans.model.ContextData;

import org.gluu.agama.user.UserRegistration;
import io.jans.agama.engine.script.LogUtils;

import java.security.SecureRandom;
import java.util.*;
import java.util.regex.Pattern;
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
    private static final String COUNTRY = "jansCountry";
    private static final String REFERRAL = "referralCode";

    private static final SecureRandom RAND = new SecureRandom();
    private static JansUserRegistration INSTANCE = null;

    private final Map<String, String> smsOtpStore = new HashMap<>();
    private final Map<String, String> emailOtpStore = new HashMap<>();

    public JansUserRegistration() {
    }

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
        // Regex: Only alphabets (uppercase and lowercase), minimum 1 character
        String regex = '''^[A-Za-z]+$''';
        Pattern pattern = Pattern.compile(regex);
        return pattern.matcher(userName).matches();
    }

    public boolean checkIfUserExists(String username, String email) {
        return !getUserEntityByUsername(username).isEmpty() || !getUserEntityByMail(email).isEmpty();
    }

    public boolean matchPasswords(String pwd1, String pwd2) {
        return pwd1 != null && pwd1.equals(pwd2);
    }

    public boolean sendSmsOtp(String phoneNumber) {
        throw new UnsupportedOperationException("Use sendSmsOtp(phoneNumber, conf) instead.");
    }

    public boolean sendSmsOtp(String phoneNumber, Map<String, String> conf) {
        try {
            LogUtils.log("Sending OTP Code via SMS to %.", phoneNumber);

            String maskedPhone = maskPhone(phoneNumber);
            String otpCode = generateOtpCode(6);

            LogUtils.log("Generated OTP code is: ", otpCode);

            String message = "Hi, your OTP Code to complete your registration is: " + otpCode;
            associateOtpWithPhone(phoneNumber, otpCode);
            
            boolean success = sendTwilioSms(phoneNumber, message, conf);

            if (success) {
                LogUtils.log("OTP has been successfully sent to % (masked: %).", phoneNumber, maskedPhone);
            }

            return success;
        } catch (Exception e) {
            LogUtils.log("Error while sending OTP via SMS to %: %", phoneNumber, e.getMessage());
            return false;
        }
    }

    public boolean validateSmsOtp(String phoneNumber, String code) {
        try {
            LogUtils.log("Validating OTP code % for phone number %.", code, phoneNumber);
            String storedCode = smsOtpStore.getOrDefault(phoneNumber, "NULL");

            if (storedCode.equalsIgnoreCase(code)) {
                smsOtpStore.remove(phoneNumber); // OTP used, remove it
                return true;
            }

            return false;
        } catch (Exception e) {
            LogUtils.log("Error validating OTP code % for phone %: %", code, phoneNumber, e.getMessage());
            return false;
        }
    }

    public boolean sendEmailOtp(String email) {
        try {
            LogUtils.log("Sending OTP to email: ", email);

            ContextData context = new ContextData(); // You can customize this if needed
            String otp = JansEmailService.getInstance().sendEmail(email, context);

            if (otp != null) {
                emailOtpStore.put(email, otp); // Save for validation
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
        Set<String> attributes = Set.of("uid", "mail", "displayName", "givenName", "sn", "userPassword", PHONE, COUNTRY,
                REFERRAL);

        User user = new User();
        attributes.forEach(attr -> {
            String val = profile.get(attr);
            if (StringHelper.isNotEmpty(val)) {
                user.setAttribute(attr, val);
            }
        });

        UserService userService = CdiUtil.bean(UserService.class);
        user = userService.addUser(user, true);

        if (user == null) {
            throw new EntryNotFoundException("User creation failed");
        }

        return getSingleValuedAttr(user, INUM_ATTR);
    }

    public Map<String, String> getUserEntityByMail(String email) {
        User user = getUser(MAIL, email);
        return extractUserInfo(user, email);
    }

    public Map<String, String> getUserEntityByUsername(String username) {
        User user = getUser(UID, username);
        return extractUserInfo(user, null);
    }

    private Map<String, String> extractUserInfo(User user, String fallbackEmail) {
        boolean found = user != null;
        String ref = fallbackEmail != null ? fallbackEmail : user != null ? user.getUserId() : "unknown";
        LogUtils.log("User lookup for %: %", ref, found ? "FOUND" : "NOT FOUND");

        if (!found)
            return new HashMap<>();

        Map<String, String> userMap = new HashMap<>();
        userMap.put(UID, getSingleValuedAttr(user, UID));
        userMap.put(INUM_ATTR, getSingleValuedAttr(user, INUM_ATTR));
        userMap.put("name", Optional.ofNullable(getSingleValuedAttr(user, GIVEN_NAME))
                .orElseGet(() -> getSingleValuedAttr(user, DISPLAY_NAME)));
        userMap.put("email", Optional.ofNullable(getSingleValuedAttr(user, MAIL)).orElse(fallbackEmail));

        return userMap;
    }

    private String getSingleValuedAttr(User user, String attribute) {
        if (user == null)
            return null;
        if (attribute.equals(UID)) {
            return user.getUserId();
        }
        Object val = user.getAttribute(attribute, true, false);
        return val != null ? val.toString() : null;
    }

    private static User getUser(String attributeName, String value) {
        UserService userService = CdiUtil.bean(UserService.class);
        return userService.getUserByAttribute(attributeName, value, true);
    }

    private String generateOtp() {
        int otp = 100000 + RAND.nextInt(900000);
        return String.valueOf(otp);
    }

    private String generateOtpCode(int length) {
        String numbers = "0123456789";
        SecureRandom random = new SecureRandom();
        char[] otp = new char[length];
        for (int i = 0; i < length; i++) {
            otp[i] = numbers.charAt(random.nextInt(numbers.length()));
        }
        return new String(otp);
    }

    private void associateOtpWithPhone(String phone, String otp) {
        smsOtpStore.put(phone, otp);
    }

    private boolean sendTwilioSms(String userName, String phoneNumber, String message, Map<String, String> conf) {
        try {
            String ACCOUNT_SID = conf.get("ACCOUNT_SID");
            String AUTH_TOKEN = conf.get("AUTH_TOKEN");
            String FROM_NUMBER = conf.get("FROM_NUMBER");

            com.twilio.Twilio.init(ACCOUNT_SID, AUTH_TOKEN);
            com.twilio.type.PhoneNumber from = new com.twilio.type.PhoneNumber(FROM_NUMBER);
            com.twilio.type.PhoneNumber to = new com.twilio.type.PhoneNumber(phoneNumber);

            com.twilio.rest.api.v2010.account.Message.creator(to, from, message).create();

            Message.creator(TO_NUMBER, FROM_NUMBER, message).create();
            
            logger.info("OTP code has been successfully send to {} on phone number {} .", userName, phone);

            return true;
        } catch (Exception e) {
            LogUtils.log("Failed to send SMS to %: %",userName, phoneNumber, e.getMessage());
            return false;
        }
    }

    private String maskPhone(String phone) {
        if (phone == null || phone.length() < 4)
            return "****";
        return "****" + phone.substring(phone.length() - 4);
    }

}