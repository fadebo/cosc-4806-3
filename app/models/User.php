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
			$_SESSION['auth'] = 1;
			$_SESSION['username'] = ucwords($username);
			unset($_SESSION['failedAuth']);
			header('Location: /home');
			die;
		} else {
			if(isset($_SESSION['failedAuth'])) {
				$_SESSION['failedAuth'] ++; //increment
			} else {
				$_SESSION['failedAuth'] = 1;
			}
			header('Location: /login');
			die;
		}
  }
    public function create($username, $password, $password2){
        $username = strtolower($username);
        
        $password = password_hash($password, PASSWORD_DEFAULT);
        $password2 = password_hash($password2, PASSWORD_DEFAULT);
        $db = db_connect();
        $statement = $db->prepare("insert into users (username, password) values (:username, :password);");
        $statement->bindValue(':username', $username);
        $statement->bindValue(':password', $password);
        $statement->execute();
    }

}
