  #!/bin/bash

  echo "-----------------------------------"
  echo "    LAMP instalacion automatica."
  echo "-----------------------------------"
  echo "-----------------------------------"
  echo "    Verificando previa instalacion. "
  echo "-----------------------------------"
  my_apache2=$(which apache2)
  my_php=$(which php)
  my_mysql=$(which mysql)

  Estado_Instalacion=-1

  if [ -z "${my_apache2}" ] && [ -z "${my_php}" ] && [ -z "${my_mysql}" ]
  then
      Estado_Instalacion=-1
    else
        Estado_Instalacion=1
        echo "-----------------------------------"
        echo "    Todo esta Instalado. "
        echo "-----------------------------------"
  fi



  if [ "${Estado_Instalacion}" -eq -1 ]
  then
    #--------------------------------------------
    #--------------------------------------------
    #--------------------------------------------
    #--------------------------------------------

  echo "-----------------------------------"
  echo "    Actualizando"
  echo "-----------------------------------"

  sudo apt-get update
  #sudo apt-get upgrade

  echo "-----------------------------------"
  echo "Proceso de instalacion apache2:"
  echo "-----------------------------------"
  my_var2=$(which apache2)
  #echo "${my_var}"
  if [ -z "${my_var2}" ]
  then
      echo "Intalando apache2."
      sudo apt-get install apache2 -y
  else
    echo "ya se instalo."
  fi

  echo "-----------------------------------"
  echo "Proceso de instalacion php:"
  echo "-----------------------------------"
  my_var2=$(which php)
  #echo "${my_var}"
  if [ -z "${my_var2}" ]
  then
      echo "Intalando php."
      sudo apt-get install php php-pear php-mysql -y
  else
    echo "ya se instalo."
  fi

  echo "-----------------------------------"
  echo "Permisos de carpeta /var/www/html "
  echo "-----------------------------------"
  DIRECTORIO=/var/www/html
  #DIRECTORIO=/var/www/html23423
  if [ -d "$DIRECTORIO" ];  then
      echo "Permisos."
      sudo chgrp www-data /var/www/html
      sudo usermod -a -G www-data pi
      sudo chmod -R 775 /var/www/html
      sudo chmod -R g+s /var/www/html
      sudo chown -R pi /var/www/html
  else
    echo "no se colocaran permisos."
  fi

  echo "-----------------------------------"
  echo "Proceso de usuario:"
  echo "-----------------------------------"

  echo 'www-data ALL=NOPASSWD: ALL' >> /etc/sudoers

  #sudo chown -R www-data:www-data /var/www  #no activar aun falta revisar si esta el usuario


  echo "-----------------------------------"
  echo "Proceso de instalacion mysql:"
  echo "-----------------------------------"
  my_var2=$(which mysql)
  #echo "${my_var}"
  if [ -z "${my_var2}" ]
  then
      echo "Intalando mysql."
      sudo apt install mysql-server -y
  else
    echo "ya se instalo."
  fi

  echo "-----------------------------------"
  echo "Proceso de instalacion Administracion web:"
  echo "-----------------------------------"
  if [ -d "$DIRECTORIO" ];  then
		cp -r /home/pi/Firmware/Web/Admin /var/www/html/Admin
		cp /home/pi/Firmware/Web/Install/index.php /var/www/html/index.php
		rm /var/www/html/index.html
  else
    echo "no se pasaron archivos"
  fi


  #--------------------------------------------
  #--------------------------------------------
  #--------------------------------------------
  #--------------------------------------------
fi
  echo "-----------------------------------"
  echo "              FIN"
  echo "-----------------------------------"


  #DIRECTORIO=/var/www/html
  #echo "-----------------------------------"
  #my_v=$(stat -c '%a' "$DIRECTORIO")
  #echo $my_v
