[#ftl output_format="HTML"]
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Email OTP Verification</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css"></head>
<body>

  
    
    
    
  
  
    <div class="bg-white shadow-md rounded px-10 pt-8 pb-10 w-full max-w-md">
      <div class="text-center mb-6">
        <img src="https://gluu.org/wp-content/uploads/2020/12/logo.png" class="mx-auto h-12" alt="Logo">
        <h2 class="text-xl font-semibold mt-4">Verify your email</h2>
      </div>

      [#assign exists = (accountExists!false)]
      [#if exists]
        <p class="text-sm text-gray-600 text-center mb-4">
          Please enter the OTP we sent to your email to continue.
        </p>
      [#else]
        <p class="text-sm text-red-600 text-center mb-4">
          This email is not associated with any account:
          <strong>${email!''}</strong>
        </p>
      [/#if]

      [#if resent]
        <div class="text-green-600 text-sm text-center mb-4">
          A new OTP has been sent to <strong>${email!''}</strong>
        </div>
      [/#if]

      [#if !matches]
        <div class="text-red-600 text-sm text-center mb-4">
          The OTP entered is incorrect. Please try again.
        </div>
      [/#if]

      <form method="post" class="space-y-6">
        <div>
          <label for="passcode" class="block text-sm font-medium text-gray-700">Enter OTP</label>
          <input type="text" name="passcode" id="passcode" pattern="[0-9]+" placeholder="000000" required="" autofocus="" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-green-500 focus:border-green-500">
        </div>

        <div class="flex items-center justify-between">
          <button type="submit" class="inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700">
            Continue
          </button>
        </div>
      </form>

      <form method="post" class="mt-4 text-center">
        <span class="text-sm text-gray-600 mr-2">Didn't receive the code?</span>
        <button type="submit" name="resend" value="" class="text-sm font-bold text-green-600 hover:underline">
          Resend Code
        </button>
      </form>
    </div>
  
</body>


</html>