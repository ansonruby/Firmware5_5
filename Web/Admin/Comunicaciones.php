
<?php

include_once('./include/config.php');


?>

<!--  desaviliar el clik derecho
<script type='text/javascript'>
	document.oncontextmenu = function(){return false}
</script>

-->

<?php

function  ValidarIP($ip)
{
	$v6 = preg_match("/^[0-9a-f]{1,4}:([0-9a-f]{0,4}:){1,6}[0-9a-f]{1,4}$/", $ip);
	$v4 = preg_match("/^([0-9]{1,3}\.){3}[0-9]{1,3}$/", $ip);

		if 			( $v6 != 0 )	return 6; 	#ipv6
		elseif 	( $v4 != 0 )	return 4; 	#ipv4
		else 									return -1; 	#desconocida

	return -1;
}


function   IP_Ete($Red)
	{
		//$Red ="eth0";
		$mm ="ifconfig -a|grep -A 1 $Red|grep -v 127.0.0.1|grep -v UP|grep -v ether|grep -v inet6|awk '{print $2}'|tr -d 'addr:'^C";
		//$mm ="ifconfig -a|grep -A 1 eth0|grep -v 127.0.0.1|grep -v UP|grep -v ether|grep -v inet6|awk '{print $2}'|tr -d 'addr:'^C";
		$temp = shell_exec($mm);
		if (strlen($temp)>=3)
		{	//echo $temp;
			$mm="	grep -A 1 $Red /etc/dhcpcd.conf|grep -v '#'|grep static|awk '{print $2}'|tr -d 'ip_address='^C";
			$temp2 = shell_exec($mm);
			if ($temp2 == $temp)
			{
				if (strlen($temp2)>=3)	{echo " ".$temp."(Estática)";}//echo $temp;}
				else 										{echo " ".$temp."(Dinámica)";}
			}
			else
			{
				if (strlen($temp2)>=3)	{echo " ".$temp.$temp2."(Estática)";}//echo $temp;}
				else 										{echo " ".$temp.$temp2."(Dinámica)";}
			}


		}
		else
		{
			 echo "NO configurada";
			 $mm="	grep -A 1 $Red /etc/dhcpcd.conf|grep -v '#'|grep static|awk '{print $2}'|tr -d 'ip_address='^C";
			 $temp2 = shell_exec($mm);
	 			if ($temp2 == $temp)
	 			{
	 				if (strlen($temp2)>=3)	{echo " ".$temp."(Estática)";}//echo $temp;}
	 				else 										{echo " ".$temp."(Dinámica)";}
	 			}
	 			else
	 			{
	 				if (strlen($temp2)>=3)	{echo " ".$temp.$temp2."(Estática)";}//echo $temp;}
	 				else 										{echo " ".$temp.$temp2."(Dinámica)";}
	 			}
		 }
	}

//IP_Ete("eth0");
function   Wifis()
	{
		$mm ="iwlist wlan0 scan | grep ESSID"; #"sudo iwlist wlan0 scan | grep ESSID";
		$temp = shell_exec($mm);
		//echo $temp;
		//echo 'no se que pasa';
		$temp=str_replace('\n','', $temp);
		$opciones = explode('ESSID:', $temp);
		//echo count($opciones);
		//$post_op = strtoupper ($_POST['button_style']);
		$post_op = $_POST['button_style'];

		for ($x = 0; $x <= count($opciones); $x+=1) {
	  	//echo  $opciones[$x]."<br>";
			//$opciones[$x] = str_replace('','"',$opciones[$x]);
			//str_replace($opciones[$x], '', $opciones[$x]);
			//substr($opciones[$x], 1, -2)
			if ( strlen($opciones[$x])>= 1)
				{
					$ID_Wifi=str_replace('"','', $opciones[$x]);
					//$ID_Wifi=str_replace('\r','', $ID_Wifi);
					echo '<option value= '.$opciones[$x];
					if(strpos ($ID_Wifi,$post_op) !== false) echo "selected";
					echo '>'.$ID_Wifi.'</option>';
				}

		}
	}


		if(isset($_POST["Conectar"]) ){
			//echo "Intentando Conectar";
			$dato ="";
			//echo  "Wifi:".$_POST['button_style'].",Pass:". $_POST['Password'];

		  $dato ="C.W:".$_POST['button_style'].".P:". $_POST['Password'];
			//echo  $dato ;

		  $fh = fopen('./include/Control_Web.txt', 'w');
		    fwrite($fh, $dato);                 //fwrite($fh, '0.Borrar.Borrar_Basedfssdfsdf');
		  fclose($fh);

        }

		if(isset($_POST["Mantener_Dinamica"]) ){
					//echo "NO se deve cer dianmica";
					$dato ="";
					//echo  "Wifi:".$_POST['button_style'].",Pass:". $_POST['Password'];

				  $dato ="C.R:".$_POST['RED'].".D";
					//echo  $dato ;

				  $fh = fopen('./include/Control_Web.txt', 'w');
				    fwrite($fh, $dato);                 //fwrite($fh, '0.Borrar.Borrar_Basedfssdfsdf');
				  fclose($fh);

		 }

		 if(isset($_POST["Confirmar"]) ){
 					//echo "NO se deve cer dianmica";
 					$dato ="";
 					//echo  "Wifi:".$_POST['button_style'].",Pass:". $_POST['Password'];

					if (ValidarIP($_POST['IP'])!=4) $message = 'No es una IP válida.';
					elseif (ValidarIP($_POST['Gateway'])!=4) $message = 'No es una Gateway válida.';
					elseif (ValidarIP($_POST['DNS'])!=4) $message = 'No es una DNS válida.';
					else {
						$message = '';
						$dato ="C.R:".$_POST['RED'].".I:".$_POST['IP'].".G:".$_POST['Gateway'].".D:".$_POST['DNS'].".E";
	 					//echo  $dato ;

	 				  $fh = fopen('./include/Control_Web.txt', 'w');
	 				    fwrite($fh, $dato);                 //fwrite($fh, '0.Borrar.Borrar_Basedfssdfsdf');
	 				  fclose($fh);

					}
 		 }




		 if(isset($_POST["Agregar"]) ){
		 		 //echo "NO deve ser dinamica";
		 		 $dato ="";
		 		 //echo  "Wifi:".$_POST['button_style'].",Pass:". $_POST['Password'];

		 		 if (ValidarIP($_POST['IP_counter'])!=4) $message2 = 'No es una IP válida.';
		 		 else {
		 			 $message2 = '';
		 			 $dato ="C.R:"."IC:".$_POST['IP_counter'];
		 			 #echo  $dato ;

		 			 $fh = fopen('./include/Control_Web.txt', 'w');
		 				 fwrite($fh, $dato);                 //fwrite($fh, '0.Borrar.Borrar_Basedfssdfsdf');
		 			 fclose($fh);

		 		 }
		 }








    ?>




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
          <h3 class="panel-title">Comunicaciones</h3>
        </div>
        <div class="panel-body">
      <!-- -------------- para detro  del titulo -------------------------- -->
			<table class="table table-hover">
			<tbody>
				<tr>
					<td style="width:30%;vertical-align:middle; padding:8px;"><strong>Ethernet</strong></td>
					<td style="width:70%; vertical-align:middle; padding:8px;"><span data-id="sysinfo_host"><?php IP_Ete("eth0");?> </span></td>
				</tr>
				<tr>
					<td style="width:30%;vertical-align:middle; padding:8px;"><strong>WIFI</strong></td>
					<td style="width:70%; vertical-align:middle; padding:8px;"><span data-id="sysinfo_host"><?php IP_Ete("wlan0");?> </span></td>
				</tr>



				</tbody>
			</table>

      <!-- ---------------------------------------------------------------- -->

        </div>
      </div>


      <!-- -------------- Configuración Wifi -------------------------- -->
      <div id="system-status" class="panel panel-default" style="margin-bottom: 5px">
        <div class="panel-heading">
          <h3 class="panel-title">Configuración Wifi</h3>
        </div>
        <div class="panel-body">

      <!-- --------------  -------------------------- -->

			<form style="width: 100%;" class="create-button-form" id="formID" method="post" action="" class="formular" >

					<input type="hidden" name="action" value="submit_button">
					<input type="hidden" id="button_id" name="button_id" value="">

					<div class="form-group">
						<label for="button_style">WIFI:</label>
						<select class="form-control" id="button_style" name="button_style">
							<?php Wifis();?>

						</select>
					</div>

					<div class="form-group">
						<label for="button_command">Password:</label>
						<input type="text" class="form-control" id="Password" <?php $Password=$_POST['Password']; echo "value='$Password'"; ?> placeholder="" name="Password">
					</div>


					<input id="button" class="btn-inverse" type="submit" value="Actualizar_Redes" name="Actualizar Redes"/>
					<input id="button" class="btn-inverse" type="submit" value="Conectar" name="Conectar"/>

			</form>

      <!-- ---------------------------------------------------------------- -->

        </div>
      </div>

      <!-- -------------- Configuración IP Estática  -------------------------- -->
      <div id="system-status" class="panel panel-default" style="margin-bottom: 5px">
        <div class="panel-heading">
          <h3 class="panel-title">Configuración IP Estática</h3>
        </div>
        <div class="panel-body">

      <!-- --------------  -------------------------- -->

			<form style="width: 100%;" class="create-button-form" id="formID" method="post" action="" class="formular" >

					<input type="hidden" name="action" value="submit_button">
					<input type="hidden" id="button_id" name="button_id" value="">
					<div class="form-group">
						<select class="form-control" id="RED" name="RED" >
							<label for="RED">RED:</label>
							<option value="WIFI" >WIFI</option>
							<option value="Ethernet">Ethernet</option>
						</select>
					</div>

					<div class="form-group">
						<label for="button_style">IP:</label>
						<input type="text" class="form-control" id="IP" <?php $IP=$_POST['IP']; echo "value='$IP'"; ?> placeholder="" name="IP" >
					</div>

					<div class="form-group">
						<label for="button_command">Gateway:</label>
						<input type="text" class="form-control" id="Gateway" <?php $Gateway=$_POST['Gateway']; echo "value='$Gateway'"; ?> placeholder="" name="Gateway">
					</div>

					<div class="form-group">
						<label for="button_command">DNS:</label>
						<input type="text" class="form-control" id="Gateway" <?php $DNS=$_POST['DNS']; echo "value='$DNS'"; ?> placeholder="" name="DNS">
					</div>



					<input id="button" class="btn-inverse" type="submit" value="Confirmar" name="Confirmar"/>
					<input id="button" class="btn-inverse" type="submit" value="Mantener_Dinamica" name="Mantener_Dinamica"/>

			</form>

      <!-- ---------------------------------------------------------------- -->
			<?php
				if(!empty($message))
				{
					echo '<div class="alert alert-danger" role="alert" style="margin-bottom:20px;">'.$message.'</div>';
				}
			?>

        </div>
      </div>








			<!-- -------------- Configuración IP Counter  -------------------------- -->
			<div id="system-status" class="panel panel-default" style="margin-bottom: 5px">
				<div class="panel-heading">
					<h3 class="panel-title">Configuración IP Counter</h3>
				</div>
				<div class="panel-body">

			<!-- --------------  -------------------------- -->

			<form style="width: 100%;" class="create-button-form" id="formID" method="post" action="" class="formular" >



					<div class="form-group">
						<label for="button_style">IP:</label>
						<input type="text" class="form-control" id="IP_counter" <?php $IP_counter=$_POST['IP_counter']; echo "value='$IP_counter'"; ?> placeholder="" name="IP_counter" >
					</div>


					<input id="button" class="btn-inverse" type="submit" value="Agregar" name="Agregar"/>


			</form>

			<!-- ---------------------------------------------------------------- -->
			<?php
				if(!empty($message2))
				{
					echo '<div class="alert alert-danger" role="alert" style="margin-bottom:20px;">'.$message2.'</div>';
				}
			?>


				</div>
			</div>














  </div>
	<!--
		<div class="content" style="display:none;">Hola, voy a desaparecer en 3 segundos!</div>
		<div class="content2" style="display:none;">Hola, soy un nuevo div!</div>
		<div id="txt" class="alert alert-success"  style="display: none">QUE PASA LOCO</div>
	-->

</body>
</html>
