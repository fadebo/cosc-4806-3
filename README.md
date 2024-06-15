Redesigned app to follow the MVC (Model-View-Controller) format 
Has a login controller and a home controller, a user model, two views, and possibly more! 
When a user creates an account, it is done through creating a new controller and a new function anemed (create)
After 3 unsuccessful login attempts, lock the user out for 60 seconds (based on the time of the last failed attempt)
Uses bootstrap
Implements a basic JavaScript and CSS countdown to display the remaining seconds before a login attempt can be accepted.
Created a private function named logAttempt to login the users attempt(good or bad) to a newly created table in the database
Modified the User model to use the database instead of the session as i figured that someone can bypass the session by using a different laptop or clear cookies to access the account even if they have more than three failed attempts in 1 minute.
