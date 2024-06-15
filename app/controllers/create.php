<?php

class Create extends Controller {

    public function index() {		
	    $this->view('create/index');
    }
    public function action(){
        $username = $_REQUEST['username'];
        $password = $_REQUEST['password'];
        $password2 = $_REQUEST['password2'];
        $user = $this->model('User');
        $user->create($username, $password, $password2);
    }
}
