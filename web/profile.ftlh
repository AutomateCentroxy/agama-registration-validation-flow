[#ftl output_format="HTML"]
<!DOCTYPE html>
<html lang="en">
<head></head>
<body><form method="post" enctype="application/x-www-form-urlencoded" id="registerForm">
  
  <!-- Username -->
  <div class="form-group">
    <label class="form-label">Username: <span class="required">*</span></label>
    <input type="text" id="uid" name="uid" pattern="[A-Za-z]+" title="Only alphabets allowed" required="" class="form-control" placeholder="Choose a username">
  </div>

  <!-- Display Name -->
  <div class="form-group">
    <label class="form-label">Display Name: <span class="required">*</span></label>
    <input type="text" id="displayName" name="displayName" required="" class="form-control" placeholder="Your full name">
  </div>

  <!-- Email -->
  <div class="form-group">
    <label class="form-label">Email: <span class="required">*</span></label>
    <input type="email" id="mail" name="mail" required="" class="form-control" placeholder="you@example.com">
  </div>

  <!-- Mobile Number -->
  <div class="form-group">
    <label class="form-label">Mobile Number: <span class="required">*</span></label>
    <input type="tel" id="jansMobile" name="jansMobile" pattern="^\+?\d{10,15}$" title="Enter a valid phone number with country code" required="" class="form-control" placeholder="+911234567890">
  </div>

  <!-- Country -->
  <div class="form-group">
    <label class="form-label">Country: <span class="required">*</span></label>
    <input type="text" id="jansCountry" name="jansCountry" required="" class="form-control" placeholder="e.g., India">
  </div>

  <!-- Referral Code -->
  <div class="form-group">
    <label class="form-label">Referral Code:</label>
    <input type="text" id="referralCode" name="referralCode" class="form-control" placeholder="Optional referral code">
  </div>

  <!-- Password -->
  <div class="form-group">
    <label class="form-label">Password: <span class="required">*</span></label>
    <input type="password" id="userPassword" name="userPassword" required="" class="form-control" placeholder="Enter your password">
  </div>

  <!-- Submit Button -->
  <div class="form-group" align="center">
    <button type="submit" class="btn btn-primary">Submit</button>
  </div>

</form></body>


</html>