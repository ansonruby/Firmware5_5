<?php

//make sure that php ssh in installed (sudo apt-get install php5-ssh2)
define('SSH_PORT', '22'); //your ssh port, defailt is "22"
define('SSH_USER', 'pi'); //your ssh username, default is "pi"
define('SSH_PASS', 'fusepong2019'); //your ssh password, default is "raspberry"

define('LOGIN_REQUIRED', false); 		// establecer en "true" si desea habilitar un sistema de inicio de sesión, o "false" para deshabilitarlo
define('LOGIN_USER', 'pi'); 				//set username for login
define('LOGIN_PASS', 'fusepong2021'); 	//set password for login

define('GUMCP_DEBUG', false); // cambia a verdadero para mostrar errores de PHP, o falso para ocultar errores

define('MEMORY_CALCULATION_METHOD', 2); //change to 1 to use the free -mo command, which may not work with all raspberrys



$gumcp_modules = array(
	'Restablecer' => array(
		'module_title' => 'Restablecer',
		'module_index_file_relative_path' => './Restablecer.php',
		'module_active' => 1,// cambie a 1 para habilitar el administrador de archivos y 0 para deshabilitarlo.
	),
	'Torniquete' => array(
		'module_title' => 'Torniquete',
		'module_index_file_relative_path' => './Torniquete.php',
		'module_active' => 1, // cambie a 1 para habilitar el administrador de archivos y 0 para deshabilitarlo.
	),
	'Comunicaciones' => array(
		'module_title' => 'Comunicaciones',
		'module_index_file_relative_path' => './Comunicaciones.php',
		'module_active' => 1, // cambie a 1 para habilitar el administrador de archivos y 0 para deshabilitarlo.
	),
	'Firmware' => array(
		'module_title' => 'Firmware',
		'module_index_file_relative_path' => './Firmware.php',
		'module_active' => 1, // cambie a 1 para habilitar el administrador de archivos y 0 para deshabilitarlo.
	),

);


if(GUMCP_DEBUG == true)
{
	error_reporting(E_ALL);
}
else
{
	error_reporting(0);
}

//dont touch from this line
session_start();
session_regenerate_id();

if(!empty($_REQUEST['login_user']) && !empty($_REQUEST['login_pass']) && $_REQUEST['login_user'] == LOGIN_USER && $_REQUEST['login_pass'] == LOGIN_PASS)
{
	$_SESSION['LOGIN_USER'] = md5(LOGIN_USER);
	$_SESSION['LOGIN_PASS'] = md5(LOGIN_PASS);
}
elseif(!empty($_REQUEST['login_user']) && !empty($_REQUEST['login_pass']))
{
	header("Location: ./login.php?action=incorrect_login");
	exit();
}



if(LOGIN_REQUIRED==true)
{
	if(isset($_SESSION['LOGIN_USER']) && $_SESSION['LOGIN_USER']==md5(LOGIN_USER) && isset($_SESSION['LOGIN_PASS']) && $_SESSION['LOGIN_PASS'] == md5(LOGIN_PASS))
	{

	}
	else
	{
		header("Location: ./login.php");
		exit();
	}
}




?>
