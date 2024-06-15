<?php require_once 'app/views/templates/headerPublic.php';
// Check for authentication errors
$error = isset($_SESSION['error']) ? $_SESSION['error'] : null;
$lockoutTime = isset($_SESSION['lockoutTime']) ? $_SESSION['lockoutTime'] : null;
$remainingTime = ($lockoutTime && time() < $lockoutTime) ? $lockoutTime - time() : 0;

unset($_SESSION['error']); // Clear the error message after displaying
?>
<main role="main" class="container">
    <div class="page-header" id="banner">
        <div class="row">
            <div class="col-lg-12">
                <h1>You are not logged in</h1>
            </div>
        </div>
    </div>
	<?php if ($error): ?>
		<div class="alert alert-danger" role="alert">
				<?php echo htmlspecialchars($error); ?>
				<?php if ($remainingTime > 0): ?>
						<p>Please wait for <span id="countdown"><?php echo $remainingTime; ?></span> seconds.</p>
				<?php endif; ?>
		</div>
	<?php endif; ?>
	
<div class="row">
    <div class="col-sm-auto">
		<form action="/login/verify" method="post" >
		<fieldset>
			<div class="form-group">
				<label for="username">Username</label>
				<input required type="text" class="form-control" name="username">
			</div>
			<div class="form-group">
				<label for="password">Password</label>
				<input required type="password" class="form-control" name="password">
			</div>
            <br>
		    <button type="submit" class="btn btn-primary">Login</button>
		</fieldset>
		</form> 
	</div>
	<p><a href="/create">Don't have an account? Create now</a>
</div>
    <?php require_once 'app/views/templates/footer.php' ?>
