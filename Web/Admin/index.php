
<?php


include_once('./include/config.php');
include_once('./include/Funciones_app.php');




//echo $_SERVER['SERVER_ADDR']; //ip del servidor

$temp = shell_exec('cat /sys/class/thermal/thermal_zone*/temp');
$temp = round($temp / 1000, 1);

$cpuusage = 100 - shell_exec("vmstat | tail -1 | awk '{print $15}'");

$clock = '';
/*$clock = shell_exec('cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq');
	$clock = round($clock / 1000);*/



//disk usage
$bytes = disk_free_space(".");
$si_prefix = array( 'B', 'KB', 'MB', 'GB', 'TB', 'EB', 'ZB', 'YB' );
$base = 1024;
$class = min((int)log($bytes , $base) , count($si_prefix) - 1);
$disk_free =  sprintf('%1.2f' , $bytes / pow($base,$class));
$bytes = disk_total_space(".");
$si_prefix = array( 'B', 'KB', 'MB', 'GB', 'TB', 'EB', 'ZB', 'YB' );
$base = 1024;
$class = min((int)log($bytes , $base) , count($si_prefix) - 1);
$disk_total = sprintf('%1.2f' , $bytes / pow($base,$class));

$disk_used = $disk_total - $disk_free;
$disk_percentage = round($disk_used / $disk_total * 100);


$operating_system = shell_exec('uname -a');

$cpu_info = shell_exec('lscpu');
$cpu_info = str_replace("\n", '. ', $cpu_info);


$uptime = shell_exec('uptime -p');

$load = sys_getloadavg();

$processes = shell_exec("ps aux | wc -l");

$top = shell_exec("top -b -n 1 | head -n 30  | tail -n 30");

$users = shell_exec("w");
$users = preg_replace('/^.+\n/', '', $users);

$disks = shell_exec("df");

$date = shell_exec("date");


//memory usage
if(MEMORY_CALCULATION_METHOD==1)
{
	$out = shell_exec('free -m');
	preg_match_all('/\s+([0-9]+)/', $out, $matches);
	list($memory_total, $memory_used, $memory_free, $memory_shared, $memory_buffers, $memory_cached) = $matches[1];

}
else
{
	$top_lines = preg_split("/\\r\\n|\\r|\\n/", $top);
	preg_match_all('/\s+([0-9]+)\s+([A-z]+)/', $top_lines[3], $matches);
	//list($memory_total, $memory_used, $memory_free, $memory_buffers) = $matches[1];
	//previous version didnt work properly on different linux versions
	for($i=0;$i<count($matches[1]);$i++)
	{
		if(strtolower($matches[2][$i])=='total')
		{
			$memory_total = $matches[1][$i];
		}
		else if(strtolower($matches[2][$i])=='free')
			{
				$memory_free = $matches[1][$i];
			}
		else if(strtolower($matches[2][$i])=='used')
			{
				$memory_used = $matches[1][$i];
			}
		else if(stristr($matches[2][$i], 'buff'))
			{
				$memory_buffers = $matches[1][$i];
			}
	}

	preg_match_all('/\s+([0-9]+)\s+([A-z]+)/', $top_lines[4], $matches);
	//list($swap_total, $swap_used, $swap_free, $memory_cached) = $matches[1];
	//previous version didnt work properly on different linux versions
	for($i=0;$i<count($matches[1]);$i++)
	{
		if(strtolower($matches[2][$i])=='total')
		{
			$swap_total = $matches[1][$i];
		}
		else if(strtolower($matches[2][$i])=='free')
			{
				$swap_free = $matches[1][$i];
			}
		else if(strtolower($matches[2][$i])=='used')
			{
				$swap_used = $matches[1][$i];
			}
		else
		{
			$memory_cached = $matches[1][$i];
		}
	}
}
$memory_percentage = round(($memory_used) / $memory_total * 100);
//$memory_percentage = round(($memory_total-$memory_free) / $memory_total * 100);
//https://unix.stackexchange.com/questions/152299/how-to-get-memory-usedram-used-using-linux-command
//$memory_percentage = round(shell_exec("free | awk 'FNR == 3 {print $3/($3+$4)*100}'"));




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


<script type="text/javascript">
var timeout = setInterval(reloadData, 10000);
function reloadData () {
$.getJSON( "./include/ajax.php?action=server_info", function( data ) {
	if(data!=null && data['top']!=null)
	{
		$.each( data, function( key, val ) {
			$('#'+key).html(val);
		});
		$( ".chart" ).each(function( index ) {
			$(this).data('easyPieChart').update($(this).closest( "span" ).text().replace(/[^0-9\.]/g,''));
			$(this).attr("data-percent",$(this).closest( "span" ).text().replace(/[^0-9\.]/g,''));
		});
	}
});


}


$(function() {

	$(".chart").easyPieChart({
		barColor: function(b) {
			return (b < 50 ? "#5cb85c" : b < 85 ? "#f0ad4e" : "#cb3935")
		},
		easing: 'easeOutBounce',
		onStep: function(from, to, percent) {
			//$(this.el).find('.percent').text(Math.round(percent));
		},
		size: 50,				//size: 160,
		scaleLength: 1,	//scaleLength: 4,
		trackWidth: 1,	//trackWidth: 8,
		//lineWidth: (8 / 1.2),
		lineCap: "square"
	});
});

//style="width:50px; height:50px; position: relative; top: -15px; left: -40px;"
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
				<a class="navbar-brand" href="./index.php"><img style="width:50px; height:50px; position: relative; top: -15px; left: -40px;" src="./static/images/inicio.png" /></a>
				</div>

				<div id="navbar" class="navbar-collapse collapse">
					<ul class="nav navbar-nav navbar-right">
						<?php include_once('./include/menu.php'); ?>
					</ul>
				</div><!--/.nav-collapse -->
			</div><!--/.container-fluid -->
		</nav>


		      <!-- -------------- Inicio -------------------------- -->
		      <div id="system-status" class="panel panel-default" style="margin-bottom: 5px">
		        <div class="panel-heading">
		          <h3 class="panel-title">Inicio</h3>
		        </div>
		        <div class="panel-body">
		      <!-- -------------- para detro  del titulo -------------------------- -->


					<table class="table table-hover">
					<tbody>

						<tr>
							<td style="width:30%;vertical-align:middle; padding:8px;"><strong>Nombre</strong></td>
							<td style="width:70%; vertical-align:middle; padding:8px;"><span data-id="sysinfo_host"><?php echo gethostname(); ?> </span></td>
						</tr>

						<tr>
							<td style="width:30%;vertical-align:middle; padding:8px;"><strong>Serial</strong></td>
							<td style="width:70%; vertical-align:middle; padding:8px;"><span data-id="sysinfo_host"><?php echo Serial(); ?> </span></td>
						</tr>

						<tr>
							<td style="width:30%;vertical-align:middle; padding:8px;"><strong>Firmware (Versión)</strong></td>
							<td style="width:70%; vertical-align:middle; padding:8px;"><span data-id="sysinfo_host"><?php echo Version_Firmware(); ?> </span></td>
						</tr>

						<tr>
							<td style="width:30%;vertical-align:middle; padding:8px;"><strong>Tiempo de actividad del sistema</strong></td>
							<td style="width:70%; vertical-align:middle; padding:8px;"><span data-id="sysinfo_uptime"><span id="uptime"><?php echo $uptime; ?></span></span></td>
						</tr>

						<tr>
							<td style="width:30%;vertical-align:middle; padding:8px;"><strong>Memoria</strong></td>
							<td style="width:70%; vertical-align:middle; padding:8px;"><span data-id="sysinfo_real_memory"><span id="memory_total"><?php echo $memory_total; ?></span> KiB Total / <span id="memory_used"><?php /*echo ($memory_used - $memory_buffers - $memory_cached);*/ echo ($memory_used); ?></span> KiB Usado</span></td>
						</tr>


						</tbody>
					</table>




		      <!-- ---------------------------------------------------------------- -->

		        </div>
		      </div>


					<!-- -------------- Información del sistema -------------------------- -->
		      <div id="system-status" class="panel panel-default" style="margin-bottom: 5px">
		        <div class="panel-heading">
		          <h3 class="panel-title">Información del sistema</h3>
		        </div>
		        <div class="panel-body">

		      <!-- -------------- Temperatura -------------------------- -->

							<div class="col-xs-12 col-sm-3 text-center">
								<span class="chart1" data-percent="<?php echo $temp; ?>">
									<span class="label1">Temperatura : </span>
									<span class="percent1"><span id="temp"><?php echo $temp; ?></span><i>°C</i></span>
								</span>
							</div>


								<div class="col-xs-12 col-sm-3 text-center">
									<span class="chart1" data-percent="<?php echo $cpuusage; ?>">
										<span class="label1">Uso de CPU : </span>
										<span class="percent1"><span id="cpuusage"><?php echo $cpuusage; ?></span><i>%</i></span>
									</span>
								</div>

								<div class="col-xs-12 col-sm-3 text-center">
									<span class="chart1" data-percent="<?php echo $disk_percentage; ?>">
										<span class="label1">Espacio en disco : </span>
										<span class="percent1"><span id="disk_percentage"><?php echo $disk_percentage; ?></span><i>%</i></span>
									</span>
								</div>

								<div class="col-xs-12 col-sm-3 text-center">
									<span class="chart1" data-percent="<?php echo $memory_percentage; ?>">
										<span class="label1">Memoria : </span>
										<span class="percent1"><span id="memory_percentage"><?php echo $memory_percentage; ?></span><i>%</i></span>
									</span>
								</div>


		      <!-- ---------------------------------------------------------------- -->

		        </div>
		      </div>


					<!-- -------------- Firmware -------------------------- -->
					<div id="system-status" class="panel panel-default" style="margin-bottom: 5px">
						<div class="panel-heading">
							<h3 class="panel-title">Firmware Actividad</h3>
						</div>
						<div class="panel-body">

					<!-- --------------  -------------------------- -->

					<table class="table">
				    <thead>
				      <tr>
				        <th>Proceso</th>
				        <th>Estado</th>
				        <!--<th>Acción</th> -->
				      </tr>
				    </thead>
				    <tbody>
							<?php echo Procesos(); ?>
							<!--
				      <tr>
				        <td># Guardian</td>
				        <td><img style="width:30px; height:30px; " src="./static/images/OK.png" /></td>
				        <td><button type="button" class="btn btn-success">Activar</button><button type="button" class="btn btn-danger">Detener</button></td>
				      </tr>
							<tr>
				        <td># Actualizador</td>
				        <td><img style="width:30px; height:30px; " src="./static/images/ERROR.png" /></td>
				        <td><button type="button" class="btn btn-success">Activar</button><button type="button" class="btn btn-danger">Detener</button></td>
				      </tr>
							<tr>
				        <td># Proceso_Actualizar</td>
				        <td><img style="width:30px; height:30px; " src="./static/images/OK.png" /></td>
				        <td><button type="button" class="btn btn-success">Activar</button><button type="button" class="btn btn-danger">Detener</button></td>
				      </tr>
							<tr>
				        <td># Chicharra</td>
				        <td><img style="width:30px; height:30px; " src="./static/images/ERROR.png" /></td>
				        <td><button type="button" class="btn btn-success">Activar</button><button type="button" class="btn btn-danger">Detener</button></td>
				      </tr>
							<tr>
				        <td># Sensor_QR</td>
				        <td><img style="width:30px; height:30px; " src="./static/images/OK.png" /></td>
				        <td><button type="button" class="btn btn-success">Activar</button><button type="button" class="btn btn-danger">Detener</button></td>
				      </tr>
							<tr>
				        <td># Led</td>
				        <td><img style="width:30px; height:30px; " src="./static/images/ERROR.png" /></td>
				        <td><button type="button" class="btn btn-success">Activar</button><button type="button" class="btn btn-danger">Detener</button></td>
				      </tr>
							<tr>
				        <td># Comunicacion_Dispostivos</td>
				        <td><img style="width:30px; height:30px; " src="./static/images/OK.png" /></td>
				        <td><button type="button" class="btn btn-success">Activar</button><button type="button" class="btn btn-danger">Detener</button></td>
				      </tr>
							<tr>
				        <td># Teclado</td>
				        <td><img style="width:30px; height:30px; " src="./static/images/Warning.png" /></td>
				        <td><button type="button" class="btn btn-success">Activar</button><button type="button" class="btn btn-danger">Detener</button></td>
				      </tr>
							<tr>
				        <td># Procesar</td>
				        <td><img style="width:30px; height:30px; " src="./static/images/Pausa.png" /></td>
				        <td><button type="button" class="btn btn-success">Activar</button><button type="button" class="btn btn-danger">Detener</button></td>
				      </tr>

				      <tr class="success">
				        <td># Sensor_QR</td>
				        <td>Doe</td>
				        <td>botones</td>
				      </tr>
				      <tr class="danger">
				        <td>Danger</td>
				        <td>Moe</td>
				        <td>mary@example.com</td>
				      </tr>
				      <tr class="info">
				        <td>Info</td>
				        <td>Dooley</td>
				        <td>july@example.com</td>
				      </tr>
							-->

				    </tbody>
				  </table>

					<!-- ---------------------------------------------------------------- -->

						</div>
					</div>

					<!--
					@reboot (sleep 45;  python /home/pi/Actualizador/Guardian.py) # Guardian
# @reboot (sleep 30;  /home/pi/Actualizador/sh/app_Actualizando.sh) # Actualizador
# @reboot (sleep 35;  python /home/pi/Actualizador/Proceso_Actualizador.py) # Proceso_Actualizar

@reboot (python /home/pi/Firmware/app/Chicharra.py) # Chicharra

@reboot (python /home/pi/Firmware/app/Sensor_QR.py) # Sensor_QR

@reboot (sudo python3.5 /home/pi/Firmware/app/Led.py) # Led

@reboot (sleep 20; python /home/pi/Firmware/app/Comunicacion_Dispostivos.py) # Comunicacion_Dispostivos

@reboot (sleep 35;  /home/pi/Firmware/sh/app_30_sleep.sh) # Teclado

#@reboot (sleep 40;  /home/pi/Firmware/sh/app_20_sleep.sh) # Procesar

					-->


		  </div>
</body>
</html>
