<?php
session_start();
session_regenerate_id();
$_SESSION['LOGIN_USER'] = 'gssfd54';
$_SESSION['LOGIN_PASS'] = '345sdf';
session_destroy();
sleep(1);
header("Location: ./login.php");
?>
