# -*- coding: utf-8 -*-
#-------------------------------------------------------
#----      importar complementos                    ----
#-------------------------------------------------------
import time
import threading

import RPi.GPIO as GPIO #Libreria Python GPIO

from lib.Lib_File import *  # importar con los mismos nombres
from lib.Lib_Rout import *  # importar con los mismos nombres

#-----------------------------------------------------------
#                       CONTANTES
#-----------------------------------------------------------

#        Entrada, Salida de los relevos
Rele =   [37,38]        #16, 19 #[21,23]

#-----------------------------------------------------------
#                       DEFINICIONES
#-----------------------------------------------------------


#-----------------------------------------------------------
#                       VARIABLES
#-----------------------------------------------------------


#-----------------------------------------------------------
#----      Funciones para el manejo de los relevos     ----
#-----------------------------------------------------------
def Actividad_Rele(Direccion):
    global Rele
    Tiempo_Rele =int(Get_File(CONF_TIEM_RELE))
    GPIO.output(Rele[Direccion], GPIO.LOW)
    time.sleep(Tiempo_Rele)
    GPIO.output(Rele[Direccion], GPIO.HIGH)


#-----------------------------------------------------------
def Comando_Rele(Direccion): #modificar a COM_TX_RELE revizar funcionamiento
    Tiempo_Rele =int(Get_File(CONF_TIEM_RELE))
    Clear_File(COM_TX_RELE)
    if Direccion == 0:      Set_File(COM_TX_RELE,"¿00000004000" + str(Tiempo_Rele) + "?") #Entrar
    elif Direccion == 1:    Set_File(COM_TX_RELE,"¿00000004010" + str(Tiempo_Rele) + "?") #Salir
    elif Direccion == 2:    Set_File(COM_TX_RELE,"¿000000040300?")                        #Cerrar


#-----------------------------------------------------------
def Entrar():
    Tipo_Comunicacion = Get_File(CONF_COMU_RELE)
    if Tipo_Comunicacion == 'T':     Comando_Rele(0)       #Para dispositivos CCCB
    if Tipo_Comunicacion == 'R':     Actividad_Rele(0)     #Para dispositivos con relevos

#-----------------------------------------------------------
def Salir():
    Tipo_Comunicacion = Get_File(CONF_COMU_RELE)
    if Tipo_Comunicacion == 'T':    Comando_Rele(1)       #Para dispositivos CCCB
    if Tipo_Comunicacion == 'R':    Actividad_Rele(1)     #Para dispositivos con relevos

#-----------------------------------------------------------
def Cerrado():
    Tipo_Comunicacion = Get_File(CONF_COMU_RELE)
    if Tipo_Comunicacion == 'T':    Comando_Rele(2)       #Para dispositivos CCCB
    if Tipo_Comunicacion == 'R':    Rele_close()          #Para cerrar pines

#-----------------------------------------------------------
def Rele_close():
    global Rele
    GPIO.output(Rele[0], GPIO.HIGH)# Entrada
    GPIO.output(Rele[1], GPIO.HIGH)# Salida

#-----------------------------------------------------------
def Direcion_Rele(Res):
    global H_S_RELE
    global H_E_RELE
    Direc = Get_File(CONF_DIREC_RELE)   #Leer_Archivo(13)  # Direccion_Torniquete
    if Res == 'Access granted-E':
        if Direc == 'D':
            #Salir()
            if H_S_RELE.isAlive() is False:
                H_S_RELE   = threading.Thread(target=Salir)
                H_S_RELE.start()
        else :
            #Entrar()
            if H_E_RELE.isAlive() is False:
                H_E_RELE   = threading.Thread(target=Entrar)
                H_E_RELE.start()

    elif Res == 'Access granted-S':
        if Direc == 'D':
            #Entrar()
            if H_E_RELE.isAlive() is False:
                H_E_RELE   = threading.Thread(target=Entrar)
                H_E_RELE.start()

        else :
            #Salir()
            if H_S_RELE.isAlive() is False:
                H_S_RELE   = threading.Thread(target=Salir)
                H_S_RELE.start()


def Ciclo_Rele():
    while (True):
        time.sleep(0.1)                # 0.05
        Comando = Get_File(COM_RELE)
        if Comando != '':
            Direcion_Rele(Comando)
            Clear_File(COM_RELE)



#-----------------------------------------------------------
#                   Configuracion local
#-----------------------------------------------------------

H_S_RELE   = threading.Thread(target=Salir)
H_E_RELE   = threading.Thread(target=Entrar)

Tipo_dispositivo =Get_File(INF_DISPO)
Tipo_dis= Tipo_dispositivo.split("\n")
print Tipo_dis[0]
if      Tipo_dis[0] == 'ABDB' : Set_File(CONF_COMU_RELE,'R')
elif    Tipo_dis[0] == 'CCCB' : Set_File(CONF_COMU_RELE,'T')
else                          : Set_File(CONF_COMU_RELE,'R')

Tipo_Comunicacion = Get_File(CONF_COMU_RELE)
print Tipo_Comunicacion

if Tipo_Comunicacion == 'R':     #Para dispositivos con relevos
    GPIO.setmode (GPIO.BOARD)
    for k in range(2):
        GPIO.setup(Rele[k], GPIO.OUT)
    Rele_close()
elif Tipo_Comunicacion == 'T':  Comando_Rele(2)       #Para dispositivos con comunicacion rs485



#-----------------------------------------------------------
#-----------------------------------------------------------
#                   Ciclo principal
#-----------------------------------------------------------
#-----------------------------------------------------------
Ciclo_Rele()




#-----------------------------------------------------------
#-----------------------------------------------------------
#                       RESUMEN y descripciones
#-----------------------------------------------------------
#-----------------------------------------------------------




#-----------------------------------------------------------
#               Pruebas de funcioanmiento
#-----------------------------------------------------------

#Actividad_Rele(1)
#Actividad_Rele(0)
#Entrar()
#Salir()
#Direcion_Rele('Access granted-E')
#Direcion_Rele('Access granted-S')
