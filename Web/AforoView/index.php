
<?php


function  Aforo()
{
	$usuarios =0;
	$salidas =0;

	$fh = fopen('/home/pi/Firmware/db/Data/Tabla_Lector.txt', 'r');
	while(!feof($fh)){

		$traer = fgets($fh);
		$lectura = trim($traer);
		#echo trim($traer);
		$porciones = explode(".", $lectura);
		$divi = count($porciones);
		#echo $divi;
		if ($porciones[$divi-3] == '4')
		{
			#echo ' : Boton';
			$salidas =$salidas + 1;
		}
		else
		{
			$usuarios =$usuarios + 1;
		}

		//echo $porciones[$divi-3]; tipos 0:rut 		, 1: qr 2:pin 4:boton no touch
		//echo $porciones[$divi-2]; tipos 0:entrada	, 1: salida
		//echo $porciones[$divi-1]; tipos 0: con 		, 1: sin   inthernet
		//echo'<br>';

	}
  #echo $a-1;

	$Total =  ($usuarios-1) - $salidas;

	#echo 'Usuarios :'. $usuarios .' : <br>';
	#echo 'salidas :'.$salidas .' : <br>';
	#echo $Total .' : <br>';

	if ($Total <=0){$Total =0;}

	return $Total;
}



?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="styles.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@700&display=swap" rel="stylesheet">
    <title>Comfamiliar - Fusepong Solutions</title>

    <script type="text/javascript">
      function actualizar(){location.reload(true);}
    //Función para actualizar cada 4 segundos(4000 milisegundos)
      setInterval("actualizar()",4000);
    </script>

</head>
<body>
    <article class="capacity_view" v-if="charged">
        <section
          class="capacity_view__header_background"></section>
        <section class="capacity_view__container">
          <section class="capacity_view__container--header">
            <div class="capacity_view__header--section">
              <img
                class="header_logo"
                src="https://fusepongsolutions.s3.us-west-2.amazonaws.com/comfamiliar_centro_recreativo/Logo-Comfamiliar-2.PNG"
                alt="">
            </div>
            <p class="capacity_view__header--title" >Comfamiliar Los Lagos</p>
            <p class="empty__class"></p>
          </section>
          <section class="capacity_view__container--capacity">
            <div
              class="capacity_view__container--full_access">
              <p>Aforo actual</p>
              <p class="access_time"><?php echo Aforo(); ?></p>
            </div>
            <div
              class="capacity_view__container--prev_access">
              <p>Disponible</p>
              <p class="access_time"><?php echo 500 -Aforo(); ?></p>
            </div>
            <div
              class="capacity_view__container--resume">
              <div class="capacity_view__capacity_resume">
                <p>Aforo permitido</p>
                <div class="capacity_view__capacity_resume--people">
                    <img src="./assets/icons/icons8-grupo-de-usuarios-hombre-hombre-96.png" alt="">
                  <p class="capacity_view__capacity_resume--time">500</p>
                </div>
              </div>
              <div class="capacity_view__capacity_resume">
                <p>Ocupación</p>
                <p class="capacity_view__capacity_resume--time"><?php echo (Aforo()*100)/500; ?>%</p>
              </div>
            </div>
          </section>
        </section>
      </article>
</body>
</html>
