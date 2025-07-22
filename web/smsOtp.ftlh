[#ftl output_format="HTML"]
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>SMS OTP Verification</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2/dist/tailwind.min.css"></head>
<body>

  
	
	
	
	
	
  
  
	<div id="content" class="md:h-screen bg-white relative flex flex-col justify-center items-center">
	  <div class="md:border md:border-gray-300 bg-white md:shadow-lg shadow-none rounded p-10 w-full max-w-md">
		<div class="flex flex-col items-center space-y-4">
		  <img src="https://gluu.org/wp-content/uploads/2020/12/logo.png" alt="logo" class="w-32">
		  <div data-i18n="otp.otp_verification" class="text-2xl font-semibold">
			OTP Verification
		  </div>

		  [#if phone??]
		  <div data-i18n="otp.otp_sent_message_frag1" class="text-sm text-gray-700">
			Enter the OTP sent to 
			<span class="font-bold">${phone}</span>
		  </div>
		  [/#if]

		  [#if errorMessage??]
		  <div class="text-sm text-red-600">${errorMessage}</div>
		  [/#if]

		  [#if !matches]
		  <div data-i18n="otp.incorrect_otp_entered" class="text-sm text-red-600">
			Incorrect OTP entered.
		  </div>
		  [/#if]

		  <form method="post" class="w-full">
			<div class="relative mb-4">
			  <label for="code" data-i18n="otp.enter_otp" class="block text-sm text-gray-700 mb-1">
				Enter OTP
			  </label>
			  <input type="text" name="passcode" id="passcode" pattern="[0-9]+" placeholder="000000" autocomplete="off" required="" autofocus="" class="w-full border border-gray-300 rounded px-3 py-2 bg-gray-50 focus:border-green-700">
			</div>
			<div class="flex justify-center mb-4">
			  <button type="submit" value="Continue" data-i18n="otp.continue" class="py-2 px-6 rounded text-white bg-green-500 hover:bg-green-600">
				Continue
			  </button>
			</div>
		  </form>

		</div>
	  </div>
	</div>
  
  
  
  
</body>

<script src="https://cdnjs.cloudflare.com/ajax/libs/i18next/2.0.22/i18next.min.js"></script><script src="./locale/loc-i18next.js"></script><script src="./locale/locale.js"></script>
</html>