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
		$username = strtolower($username);
		$db = db_connect();
    $statement = $db->prepare("select * from users WHERE username = :name;");
    $statement->bindValue(':name', $username);
    $statement->execute();
    $rows = $statement->fetch(PDO::FETCH_ASSOC);
    $pass = password_hash($password, PASSWORD_DEFAULT);
		if (password_verify($pass, $rows['password'])) {
      //Password is correct
			$_SESSION['auth'] = 1;
			$_SESSION['username'] = ucwords($username);
			unset($_SESSION['failedAuth']);
			header('Location: /home');
			die;
		} else {
      //Incorrect Password
			if(isset($_SESSION['failedAuth'])) {
				$_SESSION['failedAuth'] ++; //increment
			} else {
				$_SESSION['failedAuth'] = 1;
			}
      //Redirect back to login with error message
      $_SESSION['error'] = "Incorrect password";
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

}
