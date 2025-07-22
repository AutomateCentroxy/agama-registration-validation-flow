package org.gluu.agama.user;

import java.util.Map;

import org.gluu.agama.registration.JansUserRegistration;

public abstract class UserRegistration {

    public abstract String addNewUser(Map<String, String> profile, Map<String, String> passwordInput) throws Exception;

    public abstract boolean usernamePolicyMatch(String userName);

    public abstract boolean passwordPolicyMatch(String userPassword);
    
    public abstract String sendOTPCode(String phone);

    public abstract boolean validateOTPCode(String phone, String code);

    public abstract String sendEmail(String to);

    
    public abstract boolean checkIfUserExists(String username, String email);

    public static UserRegistration getInstance(HashMap config){
        return new JansUserRegistration(config);
    }
    
    public static UserRegistration getInstance(){
        return new JansUserRegistration();
    }
}
