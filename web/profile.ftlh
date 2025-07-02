[#ftl output_format="HTML"]
<!DOCTYPE html>
<html lang="en">
<head></head>
<body>


<form method="post" enctype="application/x-www-form-urlencoded" id="registerForm"><!-- Username --><div class="form-group"><label class="form-label">Username: <span class="required">*</span></label><input type="text" id="uid" name="uid" pattern="[A-Za-z]+" title="Name should contain only alphabets" required="" placeholder="Choose a username" class="form-control"></div><!-- Display Name --><div class="form-group"><label class="form-label">Display Name: <span class="required">*</span></label><input type="text" id="displayName" name="displayName" required="" placeholder="Enter your display name" class="form-control"></div><!-- Email --><div class="form-group"><label class="form-label">Email: <span class="required">*</span></label><input type="email" id="mail" name="mail" required="" placeholder="Enter your email address" class="form-control"></div><!-- Mobile Number --><div class="form-group"><label class="form-label">Mobile Number: <span class="required">*</span></label><input type="tel" id="jansMobile" name="jansMobile" pattern="^\+?\d{10,15}$" title="Enter a valid phone number with country code" required="" placeholder="+911234567890" class="form-control"></div><!-- Country --><div class="form-group"><label class="form-label">Country: <span class="required">*</span></label><input type="text" id="jansCountry" name="jansCountry" required="" placeholder="Enter your country" class="form-control"></div><!-- Referral Code --><div class="form-group"><label class="form-label">Referral Code:</label><input type="text" id="referralCode" name="referralCode" placeholder="Optional referral code" class="form-control"></div><!-- Password --><div class="form-group"><label class="form-label">Password: <span class="required">*</span></label><input type="password" id="userPassword" name="userPassword" required="" placeholder="Enter your password" class="form-control"></div><!-- Submit --><div align="center" class="form-group"><button type="submit" class="btn btn-primary">Submit</button></div></form>


</body>


</html>