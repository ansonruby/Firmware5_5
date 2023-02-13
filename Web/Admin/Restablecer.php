
<?php
	include_once('./include/config.php');

	function  Dominio()
	{
		$fh = fopen('/home/pi/Firmware/db/Config/Server/Dominio_Servidor.txt', 'r');
		$linea = fgets($fh);
		fclose($fh);
		return $linea;
	}
	/*
	function  mmmm()
	{

		$string = file_get_contents("/home/pi/Firmware/ComCounter/Counter/db/config.json");
		if ($string === false) {
			echo "Error";
		}

		$obj = json_decode($string, true);
		if ($obj === null) {
			echo "Error";
		}
		$obj['server_update_time']=8;
		foreach($obj as $key => $value) {
		 	echo $key . " => " . $value . "<br>";
		   }
		echo json_encode($obj);
		#file_put_contents("/home/pi/Firmware/ComCounter/Counter/db/config.json",json_encode($obj,JSON_PRETTY_PRINT));

	}
	*/

	function Data_Counter($Campo)
	{
		$string = file_get_contents("/home/pi/Firmware/ComCounter/Counter/db/config.json");
		if ($string === false) {
			echo "Error";
		}

		$obj = json_decode($string, true);
		if ($obj === null) {
			echo "Error";
		}

		return $obj[$Campo];

	}

//	echo Data_Counter('counter_password');



	function  ValidarIP($ip)
	{
		$v6 = preg_match("/^[0-9a-f]{1,4}:([0-9a-f]{0,4}:){1,6}[0-9a-f]{1,4}$/", $ip);
	  $v4 = preg_match("/^([0-9]{1,3}\.){3}[0-9]{1,3}$/", $ip);

	    if 			( $v6 != 0 )	return 6; 	#ipv6
	    elseif 	( $v4 != 0 )	return 4; 	#ipv4
	    else 									return -1; 	#desconocida

		return -1;
	}


	if(isset($_POST["Test"]) ){
			$dato ="";
			$dato =$_POST['Servidor'];

			$ip = gethostbyname($dato);

	 		if ($dato === $ip) $message = 'Verifique si esta bien escrito el dominio.';
	 		else{
				#echo ValidarIP($ip);
	 			if (ValidarIP($ip)==4){
	 				$message = '';
					#echo 'No escrive';
					$fh = fopen('./include/Control_Web.txt', 'w');
						#echo '??'.$dato;
	 					fwrite($fh, "R.TS:".$dato);
	 			 	fclose($fh);
	 			}
	 		}
	}

	if(isset($_POST["Conectar"]) ){
			$dato ="";
			$dato =$_POST['Servidor'];

			$ip = gethostbyname($dato);

 	 		if ($dato === $ip) $message = 'Verifique si esta bien escrito el dominio.';
 	 		else{
 	 			if (ValidarIP($ip)==4){
 	 				$message = '';
					$fh = fopen('./include/Control_Web.txt', 'w');
	 				 fwrite($fh, "R.CS:".$dato);
	 			 fclose($fh);
 	 			}
 	 		}


	}

	if(isset($_POST["Actualizar"]) ){

			$string = file_get_contents("/home/pi/Firmware/ComCounter/Counter/db/config.json");
			if ($string === false) {
				echo "Error";
			}

			$obj = json_decode($string, true);
			if ($obj === null) {
				echo "Error";
			}

			$obj['counter_password']=$_POST['counter_password'];
	 		$obj['local_server_port']=$_POST['local_server_port'];
	 		$obj['start_up_time']=$_POST['start_up_time'];
	 		$obj['counter_user']=$_POST['counter_user'];
	 		$obj['dinamic_access']=$_POST['dinamic_access'];
	 		$obj['scanners_port']=$_POST['scanners_port'];
	 		$obj['save_logs']=$_POST['save_logs'];
	 		$obj['server_update_time']=$_POST['server_update_time'];

			file_put_contents("/home/pi/Firmware/ComCounter/Counter/db/config.json",json_encode($obj,JSON_PRETTY_PRINT));


	}

?>

<!--  desaviliar el clik derecho
<script type='text/javascript'>
	document.oncontextmenu = function(){return false}
</script>

-->



<!DOCTYPE html>
<html lang="es">
<head>
	<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="description" content="">
	<meta name="author" content="">
	<link rel="shortcut icon" href="./static/images/Configurar2.png" type="image/png" />
	<link rel="icon" href="./static/images/Configurar2.png" type="image/png" />
	<title>Panel De Control</title>
	<link href="./static/css.php" rel="stylesheet" type="text/css">
	<script src="./static/js.php" type="text/javascript">
</script>
</head>


<script type="text/javascript">
	 $(document).ready(function() {
		 $("#ProcesoUnidad").load("./include/Proceso.php");
		 var refreshId = setInterval(function() {
			$("#ProcesoUnidad").load('./include/Proceso.php');
		}, 100);
		 $.ajaxSetup({ cache: false });
	});
</script>


<body>

	<div class="container">

		<nav class="navbar navbar-default">
			<div class="container-fluid">
				<div class="navbar-header">
					<button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
						<span class="sr-only">Toggle navigation</span>
						<span class="icon-bar"></span>
						<span class="icon-bar"></span>
						<span class="icon-bar"></span>
					</button>
				<a class="navbar-brand" href="./index.php"><img style="width:50px; height:50px; position: relative; top: -15px; left: -40px;" src="./static/images/Configurar2.png" /></a>
				</div>

				<div id="navbar" class="navbar-collapse collapse">
					<ul class="nav navbar-nav navbar-right">
						<?php include_once('./include/menu.php'); ?>
					</ul>
				</div><!--/.nav-collapse -->
			</div><!--/.container-fluid -->
		</nav>

      <!-- -------------- para nuevas cosas -------------------------- -->
      <div id="system-status" class="panel panel-default" style="margin-bottom: 5px">
        <div class="panel-heading">
          <h3 class="panel-title">Restablecer</h3>
        </div>
        <div class="panel-body">
      <!-- -------------- para detro  del titulo -------------------------- -->

          <table class="table table-hover">
					       <tbody>
									 <!--
                   <tr><td><button type="submit" class="btn btn-default" value="Borrar_Historial"			onclick="Comandos(this.value);"><i class="fa fa-plus fa-lg"></i>Borrar Historial</button></td></tr>
                   <tr><td><button type="submit" class="btn btn-default" value="Borrar_Base_de_datos" onclick="Comandos(this.value);"><i class="fa fa-plus fa-lg"></i>Base de datos local</button></td></tr>
									  -->
                   <tr><td><button type="submit" class="btn btn-default" value="Valores_de_fabrica"		onclick="Comandos(this.value);"><i class="fa fa-plus fa-lg"></i>Valores de fabrica</button></td></tr>

                </tbody>
      		</table>

      <!-- ---------------------------------------------------------------- -->

        </div>
      </div>





			<!-- -------------- Configuraciónes  Counter -------------------------- -->
			<div id="system-status" class="panel panel-default" style="margin-bottom: 5px">
				<div class="panel-heading">
					<h3 class="panel-title">Nuevo Servidor</h3>
				</div>
				<div class="panel-body">

			<!-- --------------  -------------------------- -->

			<form style="width: 100%;" class="create-button-form" id="formID" method="post" action="" class="formular" >

					<input type="hidden" name="action" value="submit_button">
					<input type="hidden" id="button_id" name="button_id" value="">

					<div class="form-group">
						<label for="button_command">Dominio:</label>
						<input type="text" class="form-control" id="Servidor"

						<?php


							//$Servidor=$_POST['Servidor'];

							//echo "value='$Servidor'";

							if (isset($_POST['Servidor'])){

								$Servidor=$_POST['Servidor'];

								echo "value='$Servidor'";

							}

							else {

								if ( Dominio() != '') {

									$Servidor=Dominio();

									echo "value='$Servidor'";

								}

							}


							?>
						placeholder="Dominio.com" name="Servidor">
					</div>

					<input id="button" class="btn btn-default" type="submit" value="Test" name="Test"/>
					<input id="button" class="btn btn-default" type="submit" value="Conectar" name="Conectar"/>

			</form>

			<!-- ---------------------------------------------------------------- -->
			<?php

				if(!empty($message))
				{
					echo '<div class="alert alert-danger" role="alert" style="margin-bottom:20px;">'.$message.'</div>';
				}

			?>
			<?php 	echo '<div id="ProcesoUnidad"> </div>';	?>

				</div>
			</div>

			<!-- -------------- Configuración Counter -------------------------- -->
			<!--
			<div id="system-status" class="panel panel-default" style="margin-bottom: 5px">
				<div class="panel-heading">
					<h3 class="panel-title">Counter</h3>
				</div>
				<div class="panel-body">



			<form style="width: 100%;" class="create-button-form" id="formID" method="post" action="" class="formular" >

				<table class="table table-hover">
				<tbody>
					<tr>
							<td style="width:30%;vertical-align:middle; padding:8px;"><strong>Counter_user:</strong></td>
								<td style="width:70%; vertical-align:middle; padding:8px;">
									<span data-id="sysinfo_disk_space">
													 <div class="input-group">
														 <span class="input-group-addon">mail:</span>
														 <input type="text" class="form-control" id="Tiempo" pattern="[1-9]"
														 placeholder="1-9" name="Tiempo" required> <!-- title="Numeros entre 1 y 9." --
													 </div>
									</span>
								</td>
					</tr>


				</tbody>
				</table>





					<div class="form-group">
						<label for="button_command">counter_user:</label>
						<input type="text" class="form-control" id="counter_user"
						<?php
							if (isset($_POST['counter_user'])){
								$counter_user=$_POST['counter_user'];
								echo "value='$counter_user'";
							}
							else {
									$counter_user=Data_Counter('counter_user');
									echo "value='$counter_user'";
							}
							?>

						placeholder="name@mail.com" name="counter_user">
					</div>

					<div class="form-group">
						<label for="button_command">counter_password:</label>
						<input type="text" class="form-control" id="counter_password"
						<?php
							if (isset($_POST['counter_password'])){
								$counter_password=$_POST['counter_password'];
								echo "value='$counter_password'";
							}
							else {
									$counter_password=Data_Counter('counter_password');
									echo "value='$counter_password'";
							}
							?>
						placeholder="password" name="counter_password">
					</div>

					<div class="form-group">
						<label for="button_command">local_server_port:</label>
						<input type="text" class="form-control" id="local_server_port"
						<?php
							if (isset($_POST['local_server_port'])){
								$local_server_port=$_POST['local_server_port'];
								echo "value='$local_server_port'";
							}
							else {
									$local_server_port=Data_Counter('local_server_port');
									echo "value='$local_server_port'";
							}
							?>
						placeholder="8080" name="local_server_port">
					</div>

					<div class="form-group">
						<label for="button_command">scanners_port:</label>
						<input type="text" class="form-control" id="scanners_port"
						<?php
							if (isset($_POST['scanners_port'])){
								$scanners_port=$_POST['scanners_port'];
								echo "value='$scanners_port'";
							}
							else {
									$scanners_port=Data_Counter('scanners_port');
									echo "value='$scanners_port'";
							}
							?>
						placeholder="Dominio.com" name="scanners_port">
					</div>

					<div class="form-group">
						<label for="button_command">start_up_time:</label>
						<input type="text" class="form-control" id="start_up_time"
						<?php
							if (isset($_POST['start_up_time'])){
								$start_up_time=$_POST['start_up_time'];
								echo "value='$start_up_time'";
							}
							else {
									$start_up_time=Data_Counter('start_up_time');
									echo "value='$start_up_time'";
							}
							?>
						placeholder="Dominio.com" name="start_up_time">
					</div>



					<div class="form-group">
						<label for="button_command">dinamic_access:</label>
						<input type="text" class="form-control" id="dinamic_access"
						<?php
							if (isset($_POST['dinamic_access'])){
								$dinamic_access=$_POST['dinamic_access'];
								echo "value='$dinamic_access'";
							}
							else {
									$dinamic_access=Data_Counter('dinamic_access');
									echo "value='$dinamic_access'";
							}
							?>
						placeholder="Dominio.com" name="dinamic_access">
					</div>


					<div class="form-group">
						<label for="button_command">server_update_time:</label>
						<input type="text" class="form-control" id="server_update_time"
						<?php
							if (isset($_POST['server_update_time'])){
								$server_update_time=$_POST['server_update_time'];
								echo "value='$server_update_time'";
							}
							else {
									$server_update_time=Data_Counter('server_update_time');
									echo "value='$server_update_time'";
							}
							?>
						placeholder="Dominio.com" name="server_update_time">
					</div>



					<div class="form-group">
						<label for="button_command">save_logs:</label>
						<input type="text" class="form-control" id="save_logs"
						<?php
							if (isset($_POST['save_logs'])){
								$save_logs=$_POST['save_logs'];
								echo "value='$save_logs'";
							}
							else {
									$save_logs=Data_Counter('save_logs');
									echo "value='$save_logs'";
							}
							?>
						placeholder="Dominio.com" name="save_logs">
					</div>





					<input id="button" class="btn btn-default" type="submit" value="Actualizar" name="Actualizar"/>

			</form>


			<?php

				if(!empty($message))
				{
					echo '<div class="alert alert-danger" role="alert" style="margin-bottom:20px;">'.$message.'</div>';
				}

			?>
			<?php 	echo '<div id="ProcesoUnidad"> </div>';	?>

				</div>
			</div>

			-->



  </div>


</body>
<script src="./include/command.js"></script>

</html>
