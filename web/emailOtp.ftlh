[#ftl output_format="HTML"]
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Email OTP Verification</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css"></head>
<body>


  
  
  
  
  



  <div class="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4 w-full max-w-md">
    
    <!-- Optional logo -->
    <div class="flex justify-center mb-4">
      <img src="/static/logo.png" alt="Logo" class="h-10">
    </div>

    <!-- Page Heading -->
    <h2 class="text-2xl font-semibold text-center mb-4">Email OTP Verification</h2>

    <!-- ✅ Show one message at a time -->
    [#assign exists = (accountExists!false)]

    [#if !exists]
      <div class="text-red-600 text-center mb-4">
        User not registered: <strong>${email}</strong>
      </div>
    [/#if]

    [#if resent &amp;&amp; exists]
      <div class="text-green-600 text-center mb-4">
        OTP has been resent to your email.
      </div>
    [/#if]

    [#if (!matches) &amp;&amp; exists]
      <div class="text-red-600 text-center mb-4">
        Incorrect OTP entered.
      </div>
    [/#if]

    <!-- Divider -->
    <div class="flex items-center justify-center mb-6">
      <hr class="flex-grow border-gray-300">
      <span class="px-2 text-sm text-gray-500">Enter the code sent to your email</span>
      <hr class="flex-grow border-gray-300">
    </div>

    <!-- OTP input form -->
    [#if exists]
    <form method="post" class="space-y-4">
      <div>
        <label for="passcode" class="block text-gray-700 font-medium mb-1">OTP Code</label>
        <input type="text" id="passcode" name="passcode" pattern="[0-9]+" placeholder="Enter OTP" required="" autofocus="" autocomplete="off" class="w-full px-4 py-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-green-500">
      </div>
      <div>
        <button type="submit" class="w-full bg-green-500 hover:bg-green-600 text-white font-semibold py-2 px-4 rounded">
          Continue
        </button>
      </div>
    </form>
    [/#if]

    <!-- Resend form -->
    [#if exists]
    <form method="post" class="mt-4 text-center">
      <p class="text-sm text-gray-600">
        Didn’t receive the code?
        <button type="submit" name="resend" value="" class="text-green-600 font-semibold hover:underline ml-1">
          Resend code
        </button>
      </p>
    </form>
    [/#if]

  </div>


</body>


</html>