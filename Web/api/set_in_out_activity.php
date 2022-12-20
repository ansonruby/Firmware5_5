
<?php


function  Dir_Torni()
{ $a =0;
	echo '{"in_out":[';
	$fh = fopen('/home/pi/Firmware/db/Data/Tabla_Lector.txt', 'r');
	while(!feof($fh)){
		// Leyendo una linea
		if ($a== 0)
		{
			echo '"';
			$a =1;}
		else {echo ',"';}
		$traer = fgets($fh);
		// Imprimiendo una linea
		echo trim($traer);
		echo '"';
	}
	echo ']}';
}

Dir_Torni();


?>
