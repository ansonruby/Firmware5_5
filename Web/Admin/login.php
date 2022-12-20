<?php
if(isset($_REQUEST['action']))
{
	switch ($_REQUEST['action']) {
		case 'incorrect_login':
			$message = 'Combinación incorrecta de usuario y contraseña';

		break;

	}
}

?>
<!DOCTYPE html>
<html lang="es">
  <head>
  	<meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">

    <meta name="author" content="">
    <meta name="description" content="">

    <link rel="shortcut icon" href="./static/images/Configurar2.png" type="image/png" />
  	<link rel="icon" href="./static/images/Configurar2.png" type="image/png" />

    <title>Pruebas</title>

    <link href="./static/css.php" rel="stylesheet" type="text/css">
  	<script src="./static/js.php" type="text/javascript"></script>


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
				<a class="navbar-brand" href="./index.php"><img style="width:50px; height:50px; position: relative; top: -15px; left: -40px;" src="./static/images/inicio.png" /></a>
				</div>

			</div><!--/.container-fluid -->
		</nav>


				<div id="system-status" class="panel panel-default" style="margin-bottom: 5px">
					<div class="panel-heading">
						<h3 class="panel-title">Bienvenido</h3>
					</div>
					<div class="panel-body">

						<?php
							if(!empty($message))
							{
								echo '<div class="alert alert-danger" role="alert" style="margin-bottom:20px;">'.$message.'</div>';
							}
						?>



							<form method="post" action="./index.php" class="form-signin">
								<div class="form-group row">
									<label for="login_user" class="col-sm-2 form-control-label">Usuario:</label>
									<div class="col-sm-10">
										<input type="text" class="form-control" name="login_user" id="login_user" placeholder="Usuario" required autofocus>
									</div>
								</div>
								<div class="form-group row">
									<label for="login_pass" class="col-sm-2 form-control-label">Contraseña:</label>
									<div class="col-sm-10">
										<input type="password" class="form-control" name="login_pass" id="login_pass" placeholder="Contraseña" required>
									</div>
								</div>
								<button type="submit" class="btn btn-primary">Entrar</button>
							</form>



					</div>


				</div>



</div>
<footer>
</footer>
<div id="dialog-placeholder"></div>
</body>
</html>
