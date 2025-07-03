[#ftl output_format="HTML"]
<!DOCTYPE html>
<html lang="en">
<head></head>
<body>

  
  
  &lt;#-- Assign default values to prevent null behavior --&gt;
	<div class="text-center">
	  <img src="https://gluu.org/wp-content/uploads/2020/12/logo.png" alt="gluu logo" class="mx-auto mb-4">
	  <h2 class="text-2xl font-bold mb-4">Verify your email
	  </h2>
	  [#if !exists]
	  <p class="text-red-600 mb-2">
		This email is not associated with any account: 
		<strong>${email!''}</strong>
	  </p>
	  [/#if]
	  [#if resentFlag]
	  <p class="text-green-600 mb-2">
		A new OTP has been sent to 
		<strong>${email!''}</strong>
	  </p>
	  [/#if]
	  [#if !matchStatus]
	  <p class="text-red-600 mb-2">
		The OTP entered is incorrect. Please try again.
	  </p>
	  [/#if]
	  <form method="post" class="space-y-4 mt-4">
		<label for="passcode" class="block text-sm font-medium text-gray-700">Enter OTP</label>
		<input type="text" id="passcode" name="passcode" pattern="[0-9]+" placeholder="000000" required="" class="w-full border border-gray-300 rounded px-3 py-2">
		<button type="submit" class="bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded">
		  Continue
		</button>
	  </form>
	  <form method="post" class="mt-2">
		<p class="text-sm">Didn't receive the code? 
		  <button type="submit" name="resend" value="" class="text-green-500 font-bold">
			Resend Code
		  </button>
		</p>
	  </form>
	</div>
  
</body>


</html>