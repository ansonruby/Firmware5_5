#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Libreria personal para procesar un qr.




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

from lib.Lib_File import *            # importar con los mismos nombres
from lib.Lib_Rout import *            # importar con los mismos nombres
from lib.Lib_Requests_Server import *   #
from lib.Lib_Networks import *   #
from lib.Fun_Dispositivo import *   #
from lib.Fun_Server import *   #
from lib.Fun_Tipo_QR import *   #

#from lib.Verificar_Usuarios import *  # importar con los mismos nombres

#-------------------------------------------------------
# inicio de variable	--------------------------------------
PSP_Mensajes = 1     # 0: NO print  1: Print
#-------------------------------------------------------

#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
#                   funciones para la peticion de usuarios
#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------
def Hora_Actual():
	tiempo_segundos = time.time()
	#print(tiempo_segundos)
	#tiempo_cadena = time.ctime(tiempo_segundos) # 1488651001.7188754 seg
	tiempo_cadena = time.strftime("%I:%M %p")
	#print(tiempo_cadena)
	return tiempo_cadena
#-------------------------------------------------------
def Filtro_Caracteres(s): # eliminar los caracteres y estructura Jason
    s = s.replace('"',"")
    s = s.replace('[',"")
    s = s.replace('{',"")
    s = s.replace(']',"")
    s = s.replace('}',"")
    s = s.replace('data:',"")
    s = s.replace(',',"\r\n")
    return s
#-------------------------------------------------------
def add_Tipos_Usuarios_Nuevos(Usuario):
	puntos = Usuario.count(".")
	# print 'Puntas_separacion: ' + str(puntos)
	# -----------------------------------------------------------------------------------------
	#           Formato 1 :         azAZ09. azAZ09                  -> sha256.id  si exite el ID entra
	# -----------------------------------------------------------------------------------------
	if puntos == 1:
		# print '-----Formato 1: azAZ09. azAZ09 '
		Add_File(TAB_USER_TIPO_1, Usuario+'\n')
		Add_File(TAB_USER_TIPO_2, Usuario+'\n')
		Add_File(TAB_USER_TIPO_2_1, Usuario+'\n')
		# print 'Nuevo'
		# -----------------------------------------------------------------------------------------
		#           Formato 3 :         09. azAZ09. azAZ09. azAZ09. 09  -> tipo.id.id.id.tiempo init.   tiken un solo uso
		# -----------------------------------------------------------------------------------------
		# -----------------------------------------------------------------------------------------
		#           Formato 2.1 :       azAZ09. azAZ09. 09. 09          -> sha256.id.tiempo init.tiempo fin.
		# -----------------------------------------------------------------------------------------
	elif puntos == 2: # revizar tipo 6 en definicion
		# print '-----Formato 2_1: azAZ09. azAZ09. 09. 09'
		s2 = Usuario.split(".")
		if s2[0] == '6':
			ID = s2[1] + '.' + s2[2]
			Add_File(TAB_USER_TIPO_6, ID+'\n')

	elif puntos == 4:
		# print '-----Formato 2_1: azAZ09. azAZ09. 09. 09'

		s2 = Usuario.split(".")
		if s2[0] == '3':
			ID = s2[1] + '.' + s2[2] + '.' + s2[3] + '.' + s2[4]
			Add_File(TAB_USER_TIPO_3, ID+'\n')
			# add_New_Tikecket(Usuario)
		else:
			if PSP_Mensajes: print '-----Formato : no definido'

#-------------------------------------------------------
def Actualizar_Usuarios_Desde_server():
	global PSP_Mensajes
	Tiempo_Actual = str(int(time.time()*1000.0))  # Tiempo()
	Ruta            = Get_Rout_server()
	ID_Dispositivo  = Get_ID_Dispositivo()

	if PSP_Mensajes: print 'Ruta:' + str(Ruta.strip()) + ', UUID:' + ID_Dispositivo

	Respuesta = Pedir_Usuarios_Activos(Ruta.strip(),Tiempo_Actual,ID_Dispositivo)

	#if PSP_Mensajes: print Respuesta

	if Respuesta.find("Error") == -1:
		Usuarios= Filtro_Caracteres (Respuesta)
		if PSP_Mensajes: print Usuarios

		Usuarios = Usuarios.split("\r\n")
		#solo llegan los tipo 1 por server por el moento desavilitado tipo 3
		#Clear_File(TAB_USER_TIPO_1)
		#Clear_File(TAB_USER_TIPO_2)
		#Clear_File(TAB_USER_TIPO_2_1)
		#Clear_File(TAB_USER_TIPO_3)

		Clear_File(TAB_USER_TIPO_1)
		Clear_File(TAB_AUTO_TIPO_1)
		Clear_File(TAB_PINES_TIPO_1)
		Clear_File(TAB_USER_TIPO_2)
		Clear_File(TAB_AUTO_TIPO_2)
		Clear_File(TAB_USER_TIPO_2_1)
		Clear_File(TAB_AUTO_TIPO_2_1)
		Clear_File(TAB_USER_TIPO_3)
		Clear_File(TAB_AUTO_TIPO_3)
		Clear_File(TAB_USER_TIPO_6)
		Clear_File(TAB_AUTO_TIPO_6)

		for Usuario in Usuarios:
			#print Usuario
			if len(Usuario) > 0:
				#print Usuario
				add_Tipos_Usuarios_Nuevos(Usuario)

		return 1

	else: return -1

#-------------------------------------------------------
def Intentos_Actualizar_Usuarios(Cantidad):
	global PSP_Mensajes
	Prioridad = Get_File(CONF_AUTORIZACION_QR).strip()
	if Prioridad == '0' or Prioridad == '3':

		Set_File(COM_LED, '8')
		for Intentos in range(Cantidad):
			if PSP_Mensajes:    print 'Intento '+str(Intentos)+', Actualizar usuarios'
			if Actualizar_Usuarios_Desde_server() == 1:
				if PSP_Mensajes:	print 'Actualisados'
				break
			else:
				if PSP_Mensajes:	print 'NO actualizo'
		Set_File(COM_LED, '0')
#-------------------------------------------------------
def Hora_Actualizacion_Usuarios(Hora_Actualizacion):

        if Hora_Actualizacion == Hora_Actual():
            while 1:
                time.sleep(1)
                if Hora_Actual() != Hora_Actualizacion : break

            if PSP_Mensajes:    print 'Actualizando Usuarios'
            Set_File(COM_LED, '8')
            Intentos_Actualizar_Usuarios(3)
            Set_File(COM_LED, '0')
#-------------------------------------------------------






#------------------------------------------------------------------------------
#                   Envio de usuarios autorizados por el dispositivos al servidor
#------------------------------------------------------------------------------
def Ping_Intento_Enviar_Usuarios_Autotizados():

	global PSP_Mensajes

	Prioridad = Get_File(CONF_AUTORIZACION_QR)
	Prioridad =Prioridad.strip()
	print Prioridad

    # ------- Prioridades de autorizacion ---------------------
    # 0 :   Servidor      -> Dispositivos -> sin counter    F1_17
    # 1 :   Counter       -> Dispositivos -> sin Servidor   offLine
    # 2 :   Servidor      -> counter      -> Dispositivos   Nuevo
    # 3 :   Counter       -> Servidor     -> Dispositivos   Nuevo
    # ---------------------------------------------------------
	if Prioridad == '0' or Prioridad == '3':
		if PSP_Mensajes:	print 'avilitado comunicacion servidor'
		Autorizaciones = Get_File(TAB_ENV_SERVER)
		if len(Autorizaciones)>=1:
			if PSP_Mensajes:
				print 'hay usuarios para enviar'
				print 'Ping antes de enviar'

			Ruta            = Get_Rout_server()
			ID_Dispositivo  = Get_ID_Dispositivo()
			Tiempo_Actual = str(int(time.time()*1000.0))  # Tiempo()

			if PSP_Mensajes: print 'Ruta:' + str(Ruta.strip()) + ', UUID:' + ID_Dispositivo

			if Status_Redes() == 1:
				if 'OK' in Ping (Ruta.strip()):
					#print Autorizaciones
					Ev = Autorizaciones.replace('\n','","')
					Ev = '{"in_out":["'+Ev+'"]}'
					Ev = Ev.replace('",""]}','"]}')
					Ev = Ev.replace(',""','')

					if PSP_Mensajes:	print Ev
					Respuesta= Enviar_Usuarios(Ruta.strip(),Tiempo_Actual,ID_Dispositivo,Ev)
					if Respuesta.find("Error") == -1:
						Clear_File(TAB_ENV_SERVER)
						#print Respuesta
						s = Respuesta
						s= Filtro_Caracteres (s)
						if len(s) != 0:
							if PSP_Mensajes:	print 'guardar usuarios que estan dentro'
							"""
						    Escrivir_nuevo(1,s)     #al que pensar si los coloco en lectura como nuevo o no
						    if PP_Mensajes:
						        print s           #que hacer con los que se quedarono
						    return 1                #se iso la entrega y se guardo los usuarios
							"""
						else:
							if PSP_Mensajes:	print 'No hay usuarios adentro'
					else:
						if PSP_Mensajes:	print 'No se puedo enviar los usuarios'		#programs una nueva entrega
				else:
					if PSP_Mensajes:	print 'No contesta el servidor'
			else:
				if PSP_Mensajes:	print 'No Hay red LAN'
		else:
			if PSP_Mensajes:	print 'No hay nada para enviar'



#---------------------------------------------------------
#  Actualizar Usuarios al iniciar el proceso
#---------------------------------------------------------
print 'Ciclo principal Actualizacion de Usuarios'

if PSP_Mensajes: print 'Prioridad: '+ str(Get_File(CONF_AUTORIZACION_QR))

Intentos_Actualizar_Usuarios(3)


while 1:
	#---------------------------------------------------------
	#  Proceso 1: Tiempo de espera para disminuir proceso
	#---------------------------------------------------------
	time.sleep(2) #minimo 1
	#---------------------------------------------------------
	# Proceso 2: Actualizar_Usuarios("12:10 AM") # 12:00 AM     03:59 PM # hora chile  10:00 PM 12:10 AM
	#---------------------------------------------------------
	if Get_File(CONF_AUTORIZACION_QR) == '0': Hora_Actualizacion_Usuarios("02:55 PM")
	#---------------------------------------------------------
	#  Proceso 3:Enviar usuarios a servidor si hay y si esta en la funcion
	#---------------------------------------------------------
	Ping_Intento_Enviar_Usuarios_Autotizados()
