
<?php
	include_once('./include/config.php');

	if(isset($_POST["Test"]) ){
			 $dato ="";
			 $dato ="R.TS:".$_POST['Servidor'];
			 //echo  $dato ;
			 $fh = fopen('./include/Control_Web.txt', 'w');
				 fwrite($fh, $dato);
			 fclose($fh);
	}

	if(isset($_POST["Conectar"]) ){
			 $dato ="";
			 $dato ="R.CS:".$_POST['Servidor'];
			 //echo  $dato ;
			 $fh = fopen('./include/Control_Web.txt', 'w');
				 fwrite($fh, $dato);
			 fclose($fh);
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
          <h3 class="panel-title">Firmware</h3>
        </div>
        <div class="panel-body">
      <!-- -------------- para detro  del titulo -------------------------- -->

          <table class="table table-hover">
					       <tbody>
                   <tr><td><button type="submit" class="btn btn-default" value="Firmware"			onclick="Comandos(this.value);"><i class="fa fa-plus fa-lg"></i>Forzar actualizacion de firmware</button></td></tr>
                </tbody>
      		</table>

      <!-- ---------------------------------------------------------------- -->
      <?php 	echo '<div id="ProcesoUnidad"> </div>';	?>
        </div>
      </div>



  </div>


</body>
<script src="./include/command.js"></script>

</html>
