
<?php
	include_once('./include/config.php');

	function  Dominio()
	{

		$fh = fopen('/home/pi/Firmware/db/Config/Server/Dominio_Servidor.txt', 'r');
		$linea = fgets($fh);
		
		fclose($fh);

		

	 return $linea;
	}
	//echo Dominio();


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
 				#echo ValidarIP($ip);
 	 			if (ValidarIP($ip)==4){
 	 				$message = '';
					$fh = fopen('./include/Control_Web.txt', 'w');
	 				 fwrite($fh, "R.CS:".$dato);
	 			 fclose($fh);
 	 			}
 	 		}


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
                   <tr><td><button type="submit" class="btn btn-default" value="Borrar_Historial"			onclick="Comandos(this.value);"><i class="fa fa-plus fa-lg"></i>Borrar Historial</button></td></tr>
                   <tr><td><button type="submit" class="btn btn-default" value="Borrar_Base_de_datos" onclick="Comandos(this.value);"><i class="fa fa-plus fa-lg"></i>Base de datos local</button></td></tr>
                   <tr><td><button type="submit" class="btn btn-default" value="Valores_de_fabrica"		onclick="Comandos(this.value);"><i class="fa fa-plus fa-lg"></i>Valores de fabrica</button></td></tr>

                </tbody>
      		</table>

      <!-- ---------------------------------------------------------------- -->

        </div>
      </div>


			<!-- -------------- Configuración Nuevo servidor -------------------------- -->
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





  </div>


</body>
<script src="./include/command.js"></script>

</html>
