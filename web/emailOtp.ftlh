[#ftl output_format="HTML"]
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>OTP Submission Form</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2/dist/tailwind.min.css"></head>
<body>


  
  
  
  
  


<div id="content" class="min-h-screen bg-white flex flex-col justify-center items-center">
  <div class="border border-gray-300 bg-white shadow-lg rounded p-8 w-full max-w-md">
    
    <!-- Gluu Logo -->
    <div class="flex justify-center mb-4">
      <img src="https://gluu.org/wp-content/uploads/2020/12/logo.png" alt="Gluu Logo" class="h-12">
    </div>

    <!-- Header -->
    <div class="text-2xl font-semibold text-center mb-4" data-i18n="otp.otp_verification">OTP Verification</div>

    <!-- Email Status / Account Existence -->
    [#assign exists = (accountExists!false)]
    <div class="text-center text-red-600 mb-2">
      [#if exists]
        <span data-i18n="otp.need_verification_msg">Verification required for your account</span>
      [#else]
        <span data-i18n="otp.user_not_registered">User not registered:</span>
        <span class="font-bold">${email}</span>
      [/#if]
    </div>

    <!-- OTP Resent Notification -->
    [#if resent]
    <div class="text-center text-green-600 mb-2" data-i18n="otp.otp_resent_msg">OTP has been resent</div>
    [/#if]

    <!-- Section Divider -->
    <div class="flex items-center my-6">
      <hr class="flex-grow border-gray-300">
      <span class="px-2 text-sm text-gray-600 bg-white" data-i18n="otp.otp_sent_message_frag1">Enter the OTP sent to your email</span>
      <hr class="flex-grow border-gray-300">
    </div>

    <!-- Invalid OTP Error -->
    [#if !matches]
    <div class="text-center text-red-600 mb-4" data-i18n="otp.incorrect_otp_entered">Incorrect OTP entered</div>
    [/#if]

    <!-- OTP Submission Form -->
    <form method="post" class="space-y-6">
      <div>
        <label for="passcode" data-i18n="otp.enter_otp" class="block text-sm font-medium text-gray-700 mb-1">Enter OTP</label>
        <input type="text" name="passcode" id="passcode" pattern="[0-9]+" placeholder="000000" required="" autofocus="" class="w-full px-4 py-2 border border-gray-300 rounded focus:outline-none focus:ring focus:ring-green-500">
      </div>

      <div class="text-center">
        <button type="submit" value="Continue" data-i18n="otp.continue" class="w-full bg-green-500 hover:bg-green-600 text-white font-semibold py-2 px-4 rounded">
          Continue
        </button>
      </div>
    </form>

    <!-- Resend OTP Form -->
    <form method="post" class="mt-4 text-center">
      <span data-i18n="otp.email_not_received">Didn't receive the email?</span>
      <button type="submit" name="resend" value="" data-i18n="otp.resent_code" class="ml-1 text-green-600 font-semibold hover:underline">
        Resend code
      </button>
    </form>
  </div>
</div>

<!-- Localization JS -->




</body>

<script src="https://cdnjs.cloudflare.com/ajax/libs/i18next/2.0.22/i18next.min.js"></script><script src="./locale/loc-i18next.js"></script><script src="./locale/locale.js"></script>
</html>