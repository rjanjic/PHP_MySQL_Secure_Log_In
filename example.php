<?php

define('MYSQL_HOST', 'localhost');
define('MYSQL_USERNAME', 'root');
define('MYSQL_PASSWORD', '');
define('MYSQL_DATABASE', 'users');
define('MYSQL_TABLE_USERS', 'users');

include 'MySQL_wrapper.class.php';
include 'MySQL_Session_Handler.class.php';
include 'User_Validation.class.php';
include 'User_Log_In.class.php';



$db = new MySQL_wrapper(MYSQL_HOST, MYSQL_USERNAME, MYSQL_PASSWORD, MYSQL_DATABASE);

$db->logQueries = TRUE;
$db->logErrors = TRUE;

// Create object
$GLOBALS['MYSQL_SESSION'] = new MySQL_Session_Handler($db, 'sessions');

$a = new User_Log_In;

$a->db = &$db;

echo '<pre>';

echo 'Session before login check:' . PHP_EOL, print_r($_SESSION, TRUE);

$loggedin = FALSE;
if ($a->loggedIn()) {
	$loggedin = TRUE;
	if (!empty($_POST['logout'])) { // Log out
		$a->logOut('example.php?loggedOut');
	}
	echo '<b>Logged in!</b>' . PHP_EOL;
	
} else {
	$loggedin = FALSE;
	if (isset($_POST['login']) && $a->logInUser($_POST['email'], $_POST['password'])) { // Login
		header('Location: example.php?loggedIn');
		$loggedin = TRUE;
	}
}


echo 'Session after login check:' . PHP_EOL, print_r($_SESSION, TRUE);


echo PHP_EOL . PHP_EOL . 'POST:' . PHP_EOL . print_r($_POST, TRUE) . PHP_EOL;

/* */
$hash = $a->hash("foobar");
echo "Hashed pass: " . $hash . PHP_EOL;
if ($a->validatePassword("foobar", $hash)) {
	echo 'Valid password' . PHP_EOL;
} else {
	echo 'Wrong password' . PHP_EOL;
}

?>
</pre>

<?php if ($loggedin): ?>
	<form method="post">
		<input type="hidden" name="logout" value="1" />
		Log out
		<input type="submit" />
	</form>
<?php else: ?>
	<form method="post">
		<input type="hidden" name="login" value="1" />
		<input type="text" name="email" value="rade@it-radionica.com" /><br />
		<input type="text" name="password" value="foobar" />
		<input type="submit" />
	</form>
<?php endif; ?>