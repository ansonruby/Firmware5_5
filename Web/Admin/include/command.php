<?php
  $dato ="";
  $dato = $_POST["Comando"];            //$dato ="nose";
  $fh = fopen('Control_Web.txt', 'w');
    fwrite($fh, $dato);                //fwrite($fh, '0.Borrar.Borrar_Basedfssdfsdf');
  fclose($fh);
?>
