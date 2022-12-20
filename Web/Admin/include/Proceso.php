<?php

  $message ="";
  $linea ="";
  $nombre_fichero ="/home/pi/Firmware/db/Status/Web/Procesos_web.txt";
  if (file_exists($nombre_fichero))
  {
    $fp = fopen($nombre_fichero, "r");
    while (!feof($fp)){
        $linea = fgets($fp);
        //echo $linea;
        $message = $linea;
    }
    fclose($fp);
  }

  $porciones = explode(",", $linea);
  //echo $porciones[0]; // porción1
  //echo $porciones[1]; // porción2

  switch($porciones[0])
  {
    case "info":         $TMesa="'alert alert-info'";      break;
    case "ok":           $TMesa="'alert alert-success'";   break;
    case "error":        $TMesa="'alert alert-danger'";    break;
    case "warning"	:    $TMesa="'alert alert-warning'";	 break;
    //case "gris":         $TMesa="'alert alert-secondary'";   break;
    //case "info2":        $TMesa="'alert alert-info'";   break;
    default:             $TMesa="''";
  }



  $message =$porciones[1];

  echo"<div class=".$TMesa."role='alert' style='margin-bottom:20px;'>".$message."</div>";

  //echo '<div class="alert alert-danger" role="alert" style="margin-bottom:20px;">'.$message.'</div>';
/*
  $dato ="";
  $dato = $_POST["Comando"];            //$dato ="nose";
  $fh = fopen('Control_Web.txt', 'w');
    fwrite($fh, $dato);                //fwrite($fh, '0.Borrar.Borrar_Basedfssdfsdf');
  fclose($fh);


  switch($Tbl["Estado"])
  							{
  								case "0"	:$ver=0;$TMesa="'Normal'";	$C1="<li>Configuracion Numero 1.</li>";break;
  								case "1"	:$ver=0;$TMesa="'success'";	$C1="<li>Comunicacion con la Unidad.</li>";break;
  								case "2"	:$ver=1;$TMesa="'error'";	$C1="<li>No se logro configuracion Numero 1.</li>";EliminarProceso();break;
  								case "FIN"	:$ver=1;$TMesa="'success'";	$C1="<li>Configuracion Numero 1 OK.</li>";break;
  							}



                <div class="alert alert-primary" role="alert">
                  This is a primary alert—check it out!
                </div>
                <div class="alert alert-secondary" role="alert">
                  This is a secondary alert—check it out!
                </div>
                <div class="alert alert-success" role="alert">
                  This is a success alert—check it out!
                </div>
                <div class="alert alert-danger" role="alert">
                  This is a danger alert—check it out!
                </div>
                <div class="alert alert-warning" role="alert">
                  This is a warning alert—check it out!
                </div>
                <div class="alert alert-info" role="alert">
                  This is a info alert—check it out!
                </div>
                <div class="alert alert-light" role="alert">
                  This is a light alert—check it out!
                </div>
                <div class="alert alert-dark" role="alert">
                  This is a dark alert—check it out!
                </div>


  */



?>
