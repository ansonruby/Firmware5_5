#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Proceso para la actualizacion del Firmware.




# ideas a implementar





"""
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
# Librerias creadas para multi procesos o hilos -------------
import datetime
import time
import commands
import sys
import socket
import os


#---------------------------------
#           Librerias personales
#---------------------------------

from lib.Lib_File import *              # importar con los mismos nombres
from lib.Lib_Rout import *              # importar con los mismos nombres
from lib.Lib_Requests_Server import *   #
from lib.Lib_Networks import *          #
from lib.Fun_Dispositivo import *       #
from lib.Fun_Server import *            #
from lib.Fun_Tipo_QR import *           #

#-------------------------------------------------------
# inicio de variable	--------------------------------

PF_Mensajes = 0     # 0: NO print  1: Print

#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
#                   funciones para el actualizador de firmware
#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
def RutaBK(Ruta):
    Rura = CONF_TIEM_RELE
    Rura = Rura.replace(FIRM,FIRMBK)
    return Rura
#------------------------
def Mantener_configuraciones():
    if PF_Mensajes:
        print 'leer los archivos del BK '

    #  -----------------------------------------
    #  MANTENER LOS PARAMETRDS DEL RELE
    #  -----------------------------------------

    #--------   MATENER TIEMPO DEL RELE
    Set_File(CONF_TIEM_RELE,Get_File(RutaBK(CONF_TIEM_RELE)))
    #--------   MATENER TIEMPO DEL RELE
    Set_File(CONF_DIREC_RELE,Get_File(RutaBK(CONF_DIREC_RELE)))
    #--------   CONFIGURACIONES DEL RELE
    Set_File(CONF_COMU_RELE,Get_File(RutaBK(CONF_COMU_RELE)))

    #  -----------------------------------------
    #  MANTENER LOS PARAMETROS DE LA FLECGA DEL TECLADO
    #  -----------------------------------------
    Set_File(CONF_FLECHA_TECLADO,Get_File(RutaBK(CONF_FLECHA_TECLADO)))

    #  -----------------------------------------
    #  MANTENER LOS PARAMETROS DE configuraciones de las autorizaiones del qr
    #  -----------------------------------------
    Set_File(CONF_AUTORIZACION_QR,Get_File(RutaBK(CONF_AUTORIZACION_QR)))






def Actualizar_Actualizador():

    #Log_Actualizador('4. Cambiar nombre de firmware en ejecucion')
    res = commands.getoutput('[ ! -f /home/pi/ActualizadorBK ] && echo "Existe" || echo "NO exiete"')
    if res == 'Existe':
        if PF_Mensajes:
            print 'Eliminar BK'
        res = commands.getoutput('sudo rm -R' + ' /home/pi/ActualizadorBK')
        print res

    res = commands.getoutput('mv /home/pi/Actualizador /home/pi/ActualizadorBK')
    res = commands.getoutput('cp -r /home/pi/Firmware/Actualizador /home/pi/Actualizador')
    res = commands.getoutput('chmod -R 755 /home/pi/Actualizador/sh/app_Actualizando.sh')
    if PF_Mensajes:
        print 'Respuesta:'+ res

def Actualizar_Web():
	res = commands.getoutput('[ -d /var/www/html/AdminBK ] && echo "Existe" || echo "NO exiete"')
	if res == 'Existe':
		if PF_Mensajes:
			print 'Eliminar BK'
		res = commands.getoutput('sudo rm -R' + ' /var/www/html/AdminBK')
		print res

	commands.getoutput('mv /var/www/html/Admin /var/www/html/AdminBK')
	commands.getoutput('cp -r /home/pi/Firmware/Web/Admin /var/www/html/Admin')

	commands.getoutput('sudo rm /var/www/html/index.php')
	commands.getoutput('cp -r /home/pi/Firmware/Web/Install/index.php /var/www/html')

	commands.getoutput('sudo chgrp www-data /var/www/html')
	commands.getoutput('sudo usermod -a -G www-data pi')
	commands.getoutput('sudo chmod -R 775 /var/www/html')
	commands.getoutput('sudo chmod -R g+s /var/www/html')
	commands.getoutput('sudo chown -R pi /var/www/html')

	if PF_Mensajes:
		print 'Respuesta:'+ res



def Hora_Actual():
	tiempo_segundos = time.time()
	#print(tiempo_segundos)
	#tiempo_cadena = time.ctime(tiempo_segundos) # 1488651001.7188754 seg
	tiempo_cadena = time.strftime("%I:%M %p")
	#print(tiempo_cadena)
	return tiempo_cadena
#---------------------------------------------------------
def Filtro_Caracteres(s): # eliminar los caracteres y estructura Jason
    s = s.replace('"',"")
    s = s.replace('[',"")
    s = s.replace('{',"")
    s = s.replace(']',"")
    s = s.replace('}',"")
    s = s.replace('data:',"")
    s = s.replace(',',"\r\n")
    return s
#---------------------------------------------------------
def Hora_Actualizacion_Firmware(Hora_Actualizacion):

	if Hora_Actualizacion == Hora_Actual():
		while 1:
		    time.sleep(1)
		    if Hora_Actual() != Hora_Actualizacion : break
		if PF_Mensajes:    print 'Actualizando el Firmware'
		Set_File(COM_ACTUALIZADOR, '1')   # Estado inicial del actualizador
#--------------------------------------------------------
def  Procedimiento_Actualizar_Firmware():
    if Get_File(COM_ACTUALIZADOR) == '1':
        Clear_File(COM_ACTUALIZADOR)
        if PF_Mensajes:
            print 'Proceso de revision del firmware'

        Vercion = Get_File(INF_VERCION)
        Vercion = Vercion.replace('\n','')
        Vercion = Vercion.strip()
        #Vercion = "2022.03.11.0"  #----- comentariar

        T_A = str(int(time.time()*1000.0))

        Ruta            = Get_Rout_server()
        ID_Dispositivo  = Get_ID_Dispositivo()
        if PF_Mensajes:
            print 'Ruta:' + str(Ruta.strip()) + ', UUID:' + ID_Dispositivo

        Respuesta = Veri_Firmware(Ruta.strip(), T_A, ID_Dispositivo, Vercion)       #enviar peticion a servidor

        if Respuesta.find("Error") == -1:
            s = Filtro_Caracteres(Respuesta)
            s=s.partition('\n')
            s1 = s[0].replace('id:','')
            ID_F = s1.replace('\r','')
            s2 = s[2].partition('\r')
            s3 = s2[0].replace('version:','')
            Vercion_F =s3.replace('\r','')
            Git_F = s2[2].replace('\r','')
            Git_F = Git_F.replace('\n','')
            Git_F = Git_F.replace('github:','')
            #--------------------------------
            if PF_Mensajes:
                print 'ID: '+ ID_F + ' vercion: '+Vercion_F + ' git: '+Git_F


            if ID_F=='OK':
                if PF_Mensajes:
                    print 'Estoy actualizado'
            else:
                if ID_F !=  ID_Dispositivo :
                    if PF_Mensajes:
                        print 'NO es para mi'
                else:
                    if Vercion.find(Vercion_F) != -1 :
                        if PF_Mensajes:
                            print 'ya esta actualizado'
                    else:
                        if PF_Mensajes:
                            print 'Devo actualizar la peticon es valida'#guarar la peticion
                        Clear_File(RESP_PET_FIRMWARE)
                        Add_File(RESP_PET_FIRMWARE,ID_F+'\n')
                        Add_File(RESP_PET_FIRMWARE,Vercion_F+'\n')
                        Add_File(RESP_PET_FIRMWARE,Git_F+'\n')
                        Set_File(STATUS_ACTUALIZADOR, '1') # Estado en 1 para el comiendso del Actualizador

        else:
            if PF_Mensajes:
                print 'No contesto el Servidor'

    if Get_File(STATUS_ACTUALIZADOR) == '3':
        if PF_Mensajes:
            print 'Hay una terminacion de firmware enviar respuesta al servidor'
        Ultimo = ""
        res16 = Get_File(MEM_ACTUALIZADOR)	#Leer_Archivo(19) # Leer en donde va el proceso de actualizacion
        #print res16
        #print len (res16)

        if len (res16) != 0:
            Faces =res16.split("\n")
            for Face in range(len(Faces)):
                c = Faces[Face]
                #print Face
                #print c
                c2 =c.split(" ")
                if len(c2[0]) >= 2:
                    #print len(c2[0])
                    #print c2[0]
                    Ultimo = c2[0]

        if PF_Mensajes:
            print Ultimo

        if Ultimo == '12.3':
            if PF_Mensajes:
                print 'Enviar respuesta al servidor Correcta'


            #----antes de enviar respues actualizar el actualizador
            Actualizar_Actualizador()
            #----antes de enviar respues actualizar la web
            Actualizar_Web()
            #----Mantener configuraciones
            Mantener_configuraciones()

            T_A = str(int(time.time()*1000.0))
            Ruta            = Get_Rout_server()
            ID_Dispositivo  = Get_ID_Dispositivo()
            if PF_Mensajes:
                print 'Ruta:' + str(Ruta.strip()) + ', UUID:' + ID_Dispositivo

            Vercion = Get_File(INF_VERCION)
            Vercion = Vercion.replace('\n','')
            Vercion = Vercion.strip()

            print Confimacion_Firmware(Ruta, T_A, ID_Dispositivo,Vercion, '')

            #----- finalizacion de la actualizacion
            Set_File(STATUS_ACTUALIZADOR,'0')
            Clear_File(MEM_ACTUALIZADOR)





#---------------------------------------------------------
while 1:
	#---------------------------------------------------------
	#  Proceso 0: Tiempo de espera para disminuir proceso
	#---------------------------------------------------------
	time.sleep(0.05)
	#---------------------------------------------------------
	#  Proceso 1: Actualizar en una hora determinada
	#---------------------------------------------------------
	Hora_Actualizacion_Firmware("12:00 AM") # 12:00 AM     03:59 PM # hora chile  10:00 PM 12:10 AM 12:34 PM
	#---------------------------------------------------------
	#  Proceso 2: procedimiento inicial de Actualizacion
	#---------------------------------------------------------
	Procedimiento_Actualizar_Firmware()
