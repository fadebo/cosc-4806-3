<?php require_once 'app/views/templates/headerPublic.php';
// Check for authentication errors
$error = isset($_SESSION['error']) ? $_SESSION['error'] : null;
unset($_SESSION['error']); // Clear the error message after displaying
?>
<main role="main" class="container">
    <div class="page-header" id="banner">
        <div class="row">
            <div class="col-lg-12">
                <h1>Create an account</h1>
            </div>
        </div>
    </div>
    <?php if ($error): ?>
        <div class="alert alert-danger" role="alert">
                <?php echo htmlspecialchars($error); ?>
        </div>
    <?php endif; ?>
<div class="row">
    <div class="col-sm-auto">
    <form action="/create/action" method="post" >
    <fieldset>
      <div class="form-group">
        <label for="username">Username</label>
        <input required type="text" class="form-control" name="username">
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input required type="password" class="form-control" name="password">
      </div>
        <div class="form-group">
            <label for="password2">Confirm Password</label>
            <input required type="password" class="form-control" name="password2">
          </div>
            <br>
        <button type="submit" class="btn btn-primary">Sign UP</button>
    </fieldset>
    </form> 
  </div>
    <p><a href="/login">Already have an account? Login now</a>
</div>
    <?php require_once 'app/views/templates/footer.php' ?>
