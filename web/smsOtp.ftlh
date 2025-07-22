[#ftl output_format="HTML"]
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>OTP Verification</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2/dist/tailwind.min.css"></head>
<body>

  
    
    
    
    
    
  
  
    <div id="content" class="md:h-screen bg-white relative flex flex-col justify-center items-center">
      <div class="md:border md:border-gray-300 bg-white md:shadow-lg shadow-none rounded p-10 w-full max-w-md">
        <div class="flex flex-col items-center space-y-4">
          <img src="https://gluu.org/wp-content/uploads/2020/12/logo.png" alt="logo" class="w-32">
          <div class="text-2xl font-semibold" data-i18n="otp.otp_verification">OTP Verification</div>

          [#if phone??]
            <div class="text-sm text-gray-700">Enter the OTP sent to <span class="font-bold">${phone}</span></div>
          [#else]
            <div class="text-sm text-red-600">No phone number is associated with your account.</div>
          [/#if]

          [#if resent]
            <div class="text-sm text-green-600" data-i18n="otp.otp_resent_msg">A new code has been sent.</div>
          [/#if]

          [#if errorMessage??]
            <div class="text-sm text-red-600">${errorMessage}</div>
          [/#if]

          <form method="post" class="w-full" onsubmit="return handleFormValidation();">
            <div class="flex justify-between mb-4">
              <input type="number" id="1" min="0" max="9" maxlength="1" class="m-1 border w-10 h-10 text-center rounded">
              <input type="number" id="2" min="0" max="9" maxlength="1" class="m-1 border w-10 h-10 text-center rounded">
              <input type="number" id="3" min="0" max="9" maxlength="1" class="m-1 border w-10 h-10 text-center rounded">
              <input type="number" id="4" min="0" max="9" maxlength="1" class="m-1 border w-10 h-10 text-center rounded">
              <input type="number" id="5" min="0" max="9" maxlength="1" class="m-1 border w-10 h-10 text-center rounded">
              <input type="number" id="6" min="0" max="9" maxlength="1" class="m-1 border w-10 h-10 text-center rounded">
            </div>

            <input type="hidden" id="code" name="code">
            <input type="hidden" id="hasRequestedNewCode" name="hasRequestedNewCode">

            <div class="flex justify-center mb-4">
              <button type="submit" class="py-2 px-6 rounded text-white bg-green-500 hover:bg-green-600">Continue</button>
            </div>
          </form>

          <form method="post">
            <div class="text-sm text-gray-700">
              Didn't receive the code?
              <button type="submit" id="resendButton" name="resend" value="true" class="ml-1 text-green-600 font-bold">Resend</button>
            </div>
          </form>
        </div>
      </div>
    </div>

    
  
</body>

<script>
      window.onload = function () {
        const form = document.querySelector("form");
        const resendBtn = document.getElementById("resendButton");
        const firstInput = document.getElementById("1");

        if (resendBtn) {
          resendBtn.onclick = function () {
            document.getElementById("hasRequestedNewCode").value = "yes";
            form.submit();
          };
        }

        if (firstInput) {
          firstInput.onpaste = function (e) {
            let pasted = (e.clipboardData || window.clipboardData).getData('text').slice(0, 6);
            let inputs = document.querySelectorAll('input[type="number"]');
            inputs.forEach((input, i) => input.value = pasted.charAt(i) || '');
            e.preventDefault();
          };
        }
      };

      function handleFormValidation() {
        if (document.getElementById("hasRequestedNewCode").value === "yes") {
          return true;
        }

        let code = "";
        let inputs = document.querySelectorAll('input[type="number"]');
        inputs.forEach(input => code += input.value);

        if (code.length !== 6) {
          alert("Please enter a 6-digit OTP code.");
          return false;
        }

        document.getElementById("code").value = code;
        return true;
      }
    </script>
</html>