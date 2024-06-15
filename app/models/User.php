<?php

class User {

    public $username;
    public $password;
    public $auth = false;

    public function __construct() {
        
    }

    public function test () {
      $db = db_connect();
      $statement = $db->prepare("select * from users;");
      $statement->execute();
      $rows = $statement->fetch(PDO::FETCH_ASSOC);
      return $rows;
    }

  public function authenticate($username, $password) {
        /*
         * if username and password good then
         * $this->auth = true;
         */
    
		// $username = strtolower($username);
  //   // Initialize the failed login attempts if not set
  //   if (!isset($_SESSION['failedAuth'])) {
  //       $_SESSION['failedAuth'] = 0;
  //   }

  //   // Initialize the lockout time if not set
  //   if (!isset($_SESSION['lockoutTime'])) {
  //       $_SESSION['lockoutTime'] = 0;
  //   }

    //decided to use the database instead of the session 
    
    
    // // Check if the user is currently locked out
    // if (time() < $_SESSION['lockoutTime']) {
    //     $_SESSION['error'] = "Too many failed login attempts. Please try again in 60 seconds.";
    //     $this->logAttempt($username, 'bad'); // Log the failed attempt
    //     header('Location: /login');
    //     exit;
    // }

		$db = db_connect();

    // Check recent failed attempts
    $statement = $db->prepare("SELECT COUNT(*) AS failed_attempts, MAX(timestamp) AS last_attempt FROM login_attempts WHERE username = :username AND attempt = 'bad' AND timestamp > (NOW() - INTERVAL 1 MINUTE)");
    $statement->bindValue(':username', $username);
    $statement->execute();
    $result = $statement->fetch(PDO::FETCH_ASSOC);

    $failedAttempts = $result['failed_attempts'];
    $lastAttempt = strtotime($result['last_attempt']);
    // Check if the user has exceeded the maximum number of failed attempts
    if ($failedAttempts >= 3 && (time() - $lastAttempt) < 60) {
        $_SESSION['lockoutTime'] = $lastAttempt + 60; // Store the lockout end time
        $_SESSION['error'] = "Too many failed login attempts. Please try again in 60 seconds.";
        $this->logAttempt($username, 'bad'); // Log the failed attempt
        header('Location: /login');
        exit;
    }

    // Check if the username and password match
    $statement = $db->prepare("select * from users WHERE username = :name;");
    $statement->bindValue(':name', $username);
    $statement->execute();
    $rows = $statement->fetch(PDO::FETCH_ASSOC);
   // $pass = password_hash($password, PASSWORD_DEFAULT);
		if (password_verify($password, $rows['password'])) {
      //Password is correct
			$_SESSION['auth'] = 1;
			$_SESSION['username'] = ucwords($username);
      unset($_SESSION['failedAuth']); // Clear any previous failed attempts
      unset($_SESSION['lockoutTime']); // Clear lockout time
      $this->logAttempt($username, 'good'); // Log the successful attempt
			header('Location: /home');
			die;
		} else {
      // Incorrect password
      // $_SESSION['failedAuth']++;
      // if ($_SESSION['failedAuth'] >= 3) {
      //     $_SESSION['lockoutTime'] = time() + 60; // Set lockout time for 60 seconds
      //     $_SESSION['error'] = "Too many failed login attempts. Please try again in 60 seconds.";
      // } else {
          $_SESSION['error'] = "Incorrect password";
     // }
          $this->logAttempt($username, 'bad'); // Log the failed attempt
          //Redirect back to login with error message
			     header('Location: /login');
			     die;
		}
  }
    public function create($username, $password, $password2){
      $username = strtolower($username);
      $db = db_connect();
      $statement = $db->prepare("select * from users WHERE username = :name;");
      $statement->bindValue(':name', $username);
      $statement->execute();
      
      if($statement->rowCount() != 0) {
        $_SESSION['error'] = "Username already exists";
        header('Location: /create');
        exit;
      }
      // Validate passwords
      $passwordValidationErrors = [];

      // Check if passwords match
      if ($password !== $password2) {
          $passwordValidationErrors[] = "Passwords do not match";
      }

      // Check password length
      if (strlen($password) < 10) {
          $passwordValidationErrors[] = "Password length must be at least 10 characters";
      }

      // Check for at least one lowercase letter
      if (!preg_match('/[a-z]/', $password)) {
          $passwordValidationErrors[] = "Password must contain at least one lowercase letter";
      }

      // Check for at least one uppercase letter
      if (!preg_match('/[A-Z]/', $password)) {
          $passwordValidationErrors[] = "Password must contain at least one uppercase letter";
      }

      // Check for at least one number
      if (!preg_match('/[0-9]/', $password)) {
          $passwordValidationErrors[] = "Password must contain at least one number";
      }

      // Check for at least one special character
      if (!preg_match('/[^A-Za-z0-9]/', $password)) {
          $passwordValidationErrors[] = "Password must contain at least one special character";
      }

      // If there are validation errors, store them in session and redirect
      if (!empty($passwordValidationErrors)) {
          $_SESSION['error'] = implode(", ", $passwordValidationErrors);
          header('Location: /create');
          exit;
      }

      // Hash the password
      $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
      $db = db_connect();
      $statement = $db->prepare("insert into users (username, password) values (:username, :password);");
      $statement->bindValue(':username', $username);
      $statement->bindValue(':password', $hashedPassword);
      $statement->execute();

      header('Location: /login'); // Redirect back to the login page
    }

  private function logAttempt($username, $attempt) {
      // Connect to database
      $db = db_connect();
      // Prepare and execute SQL query to insert log
      $statement = $db->prepare("INSERT INTO login_attempts (username, attempt) VALUES (:username, :attempt)");
      $statement->bindValue(':username', $username);
      $statement->bindValue(':attempt', $attempt);
      $statement->execute();
  }

}
