<?php

define('DATA_Creacion'    , '/home/pi/.ID/Datos_Creacion.txt');                   // Datos de creacion Firmware.
define('README_Firmware'  , '/home/pi/Firmware/README.md');                       // Datos de creacion Firmware.
define('VER_Firmware'     , '/home/pi/Firmware/db/Config/Vercion/Vercion_Firmware.txt');  // Datos de creacion Firmware.
define('PROCESS_Firmware' , '/home/pi/Firmware/auto/Procesos.txt');               // Datos de creacion Firmware.


function   Serial()
	{
		$dato ="";
		$dato .= "( ";

		$fp = fopen(DATA_Creacion, "r");
		$linea = fgets($fp);
		$dato .= $linea;
		$linea = fgets($fp);
		$dato .= " -XXXXX- ";
		$linea = fgets($fp);
		$dato .= $linea;
		fclose($fp);
		$dato .= " )";

		return $dato;
	}


function   Version_Firmware()
	{
		$dato ="";

		$fp = fopen(README_Firmware, "r");
		$linea = fgets($fp);
		$dato .= $linea;
		fclose($fp);

		$dato .= " (";

		$fp = fopen(VER_Firmware, "r");
		$linea = fgets($fp);
		$dato .= $linea;
		fclose($fp);

		$dato .= ")";

		return $dato;
	}

	function   Procesos()
		{
			$dato ="";

			$fp = fopen(PROCESS_Firmware, "r");
					//$linea = fgets($fp);
					//$dato .= $linea;
					while(!feof($fp)) {
						$linea = fgets($fp);
						#echo strlen($linea);
						if (strlen($linea) >=1){
							//echo $linea . "<br />";
							$porciones = explode("#", $linea);
							$mm = 'ps aux | grep '.$porciones[1];//. "<br />";
							//echo $mm. "<br />";
							$temp = shell_exec($mm);
							//echo $temp. "<br />";
							$Apariciones = substr_count($temp, "pi");
							//echo $porciones[1]."  ". $Apariciones. "<br />";
							//echo $temp;
							//echo $porciones[1] . "<br />";
							$dato .= "<tr><td>".$porciones[1]."</td><td><img style='width:30px; height:30px;' ";
							if  ($Apariciones >= 3) 		$dato .= "  src='./static/images/OK.png' /></td>";
							else  											$dato .= "  src='./static/images/ERROR.png' /></td>";
							//echo "<td><button type='button' class='btn btn-success'>Activar</button><button type='button' class='btn btn-danger'>Detener</button></td></tr>";
							$dato .= "</tr>";
						}
					}

			fclose($fp);


			return $dato;
		}




    ?>
