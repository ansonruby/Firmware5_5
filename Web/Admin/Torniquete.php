
<?php

include_once('./include/config.php');



if(isset($_POST["Cambiar"]) ){
			//echo "NO se deve cer dianmica";
			$dato ="";
			//echo  "Tiempo:".$_POST['Tiempo'].", Boton:". $_POST['Tor'];

			$dato ="T.T:".$_POST['Tiempo'].".D:". $_POST['Tor'];
			//echo  $dato ;

			$fh = fopen('./include/Control_Web.txt', 'w');
				fwrite($fh, $dato);                 //fwrite($fh, '0.Borrar.Borrar_Basedfssdfsdf');
			fclose($fh);



 }


 function  Dir_Torni()
 {

	 $fh = fopen('/home/pi/Firmware/db/Config/Rele/Direccion_Rele.txt', 'r');
		 $linea = fgetc($fh);
	 fclose($fh);

 	return $linea;
 }

 function  Tiem_Torni()
 {

	$fh = fopen('/home/pi/Firmware/db/Config/Rele/Tiempo_Rele.txt', 'r');
		$linea = fgetc($fh);
	fclose($fh);

	 return $linea;
 }


//echo Dir_Torni();
//echo Tiem_Torni();





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
<!--
<script type="text/javascript" charset="utf-8" src="./include/Validaciones/js/jquery-1.8.2.min.js"></script>
<script type="text/javascript" charset="utf-8" src="./include/Validaciones/js/languages/jquery.validationEngine-es.js"></script>
	<script type="text/javascript" charset="utf-8" src="./include/Validaciones/js/jquery.validationEngine.js"></script>
-->

<script type='text/javascript'>
var input = document.getElementById('Tiempo');
		input.oninvalid = function(event) {
    event.target.setCustomValidity('Username should only contain lowercase letters. e.g. john');
}

</script>

<script type="text/javascript">
	 $(document).ready(function() {
		 $("#ProcesoUnidad").load("./include/Proceso.php");
		 var refreshId = setInterval(function() {
			$("#ProcesoUnidad").load('./include/Proceso.php');
		}, 100);
		 $.ajaxSetup({ cache: false });
	});
</script>

</head>
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
          <h3 class="panel-title">Torniquete</h3>
        </div>
        <div class="panel-body">
      <!-- -------------- para detro  del titulo -------------------------- -->
          <?php //echo "ejhsjfdh que paso"; ?>
					<!--
          <table class="table table-hover">
					<tbody>
						<tr>
							<td style="width:30%;vertical-align:middle; padding:8px;"><strong>Salir por:</strong></td>
  							<td style="width:70%; vertical-align:middle; padding:8px;">
                  <span data-id="Direcion_Torniquete">
                    <label class="radio-inline"><input type="radio" name="optradio" checked>Izquierda</label>
                    <label class="radio-inline"><input type="radio" name="optradio">Derecha</label>
                  </span>
                </td>
						</tr>
						<tr>

            <tr>
                <td style="width:30%;vertical-align:middle; padding:8px;"><strong>Tiempo relevos</strong></td>
                  <td style="width:70%; vertical-align:middle; padding:8px;">
                    <span data-id="sysinfo_disk_space">
                          <form>
                             <div class="input-group">
                               <span class="input-group-addon">Segundos:</span>
                               <input id="msg" type="text" class="form-control" name="msg" placeholder="1-9">
                             </div>
                          </form>
                    </span>
                  </td>
            </tr>

						<tr><td><button type="button" class="btn btn-default" value="Cambiar" 			onclick="Torniquete_Comandos(this.value);"><i class="fa fa-plus fa-lg"></i>Cambiar</button></td></tr>

          </tbody>
          </table>
					checked
				-->


					<form style="width: 100%;" class="create-button-form" id="formID" method="post" action="" class="formular" >

						<table class="table table-hover">
						<tbody>

							<tr>
								<td style="width:30%;vertical-align:middle; padding:8px;"><strong>Salir por:</strong></td>
	  							<td style="width:70%; vertical-align:middle; padding:8px;">
	                  <span data-id="Direcion_Torniquete">
	                    <label class="radio-inline"><input type="radio" value="Izquierda" name="Tor"	<?php

											if (isset($_POST['Tor'])){
												if($_POST['Tor'] == "Izquierda") echo "checked";
											}
											else {
												if ( Dir_Torni() == 'I') {
													echo "checked";
												}
											}




											?> >Izquierda</label>
	                    <label class="radio-inline"><input type="radio" value="Derecha" 	name="Tor"	<?php


											if (isset($_POST['Tor'])){
												if($_POST['Tor'] == "Derecha") echo "checked";
											}
											else {
												if ( Dir_Torni() == 'D') {
											 		echo "checked";
											 	}
											}

												?> >Derecha</label>
	                  </span>
	                </td>
							</tr>
							<tr>


	            <tr>
	                <td style="width:30%;vertical-align:middle; padding:8px;"><strong>Tiempo relevos</strong></td>
	                  <td style="width:70%; vertical-align:middle; padding:8px;">
	                    <span data-id="sysinfo_disk_space">
	                             <div class="input-group">
	                               <span class="input-group-addon">Segundos:</span>
	                               <input type="text" class="form-control" id="Tiempo" pattern="[1-9]"  <?php

																 if (isset($_POST['Tiempo'])){
					 												$Tiempo=$_POST['Tiempo']; echo "value='$Tiempo'";
					 											}
					 											else {
																	$Tiempo=Tiem_Torni(); echo "value='$Tiempo'";

					 											}

																 //$Tiempo=$_POST['Tiempo']; echo "value='$Tiempo'";


																 ?> placeholder="1-9" name="Tiempo" required> <!-- title="Numeros entre 1 y 9." -->
	                             </div>
	                    </span>
	                  </td>
	            </tr>

							<tr>
										<td style="width:30%;vertical-align:middle; padding:8px;"><strong></strong></td>
						 			 <td style="width:70%; vertical-align:middle; padding:8px;">
						 				 <span data-id="sysinfo_disk_space">
						 						<input id="button" class="btn-inverse" type="submit" value="Cambiar" name="Cambiar"/>
						 				 </span>
						 			 </td>
						  </tr>



						</tbody>
						</table>

					</form>

					<?php 	echo '<div id="ProcesoUnidad"> </div>';	?>

      <!-- ---------------------------------------------------------------- -->

        </div>
      </div>
  </div>


</body>
</html>
