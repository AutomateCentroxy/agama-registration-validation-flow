[#ftl output_format="HTML"]
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Set Password
	</title><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css"></head>
<body>

  
	
	
	
	
  
  
	<div class="container">
	  <div class="header">
		<i class="fas fa-lock">
		</i> Set Your Password
	  </div>
	  <!-- Show server-side error if any -->
	  [#if errorMessage?has_content]
	  <div role="alert" align="center" class="alert alert-danger error-message">
		<p>${errorMessage}
		</p>
	  </div>
	  [/#if]
	  <form method="post" onsubmit="return validatePasswords()">
		<div class="form-group">
		  <label for="password" class="form-label">Password:</label>
		  <input type="password" id="password" name="userPassword" required="" placeholder="Enter your password" class="form-control">
		</div>
		<div class="form-group">
		  <label for="confirmPassword" class="form-label">Confirm Password:</label>
		  <input type="password" id="confirmPassword" name="confirmPassword" required="" placeholder="Re-enter your password" class="form-control">
		  <div id="js-error" class="error-message">
		  </div>
		</div>
		<button type="submit" class="btn">Continue</button>
	  </form>
	</div>
  
  
  
</body>
<style>
	body {
	  font-family: Arial, sans-serif;
	  background-color: #f8f9fa;
	  display: flex;
	  justify-content: center;
	  align-items: center;
	  height: 100vh;
	  margin: 0;
	}
	.container {
	  width: 100%;
	  max-width: 400px;
	  background: white;
	  border-radius: 5px;
	  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
	  padding: 30px;
	  text-align: center;
	}
	.header {
	  font-size: 20px;
	  font-weight: bold;
	  margin-bottom: 20px;
	  background-color: #28a745;
	  color: white;
	  padding: 15px;
	  border-radius: 5px 5px 0 0;
	}
	.form-group {
	  margin-bottom: 20px;
	  text-align: left;
	}
	.form-label {
	  display: block;
	  font-weight: bold;
	  margin-bottom: 5px;
	}
	.form-control {
	  width: 100%;
	  padding: 10px;
	  font-size: 14px;
	  border: 1px solid #ced4da;
	  border-radius: 5px;
	}
	.btn {
	  background-color: #007bff;
	  color: white;
	  border: none;
	  padding: 10px 20px;
	  font-size: 16px;
	  border-radius: 5px;
	  cursor: pointer;
	}
	.btn:hover {
	  background-color: #0056b3;
	}
	.error-message, .alert-danger {
	  color: red;
	  font-size: 13px;
	  margin-top: 10px;
	}
  </style>
<script>
	function validatePasswords() {
	  const pass = document.getElementById("password").value;
	  const confirm = document.getElementById("confirmPassword").value;
	  const error = document.getElementById("js-error");
	  if (pass.length < 6) {
		error.textContent = "Password must be at least 6 characters long.";
		return false;
	  }
	  if (pass !== confirm) {
		error.textContent = "Passwords do not match!";
		return false;
	  }
	  error.textContent = "";
	  return true;
	}
  </script>
</html>