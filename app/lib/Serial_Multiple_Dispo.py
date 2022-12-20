# -*- coding: utf-8 -*-
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Libreria personal para el manejo del serson lector qr por serial.




# ideas a implementar





"""
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------

#-------------------------------------------------------
#----      importar complementos                    ----
#-------------------------------------------------------
import serial
import os, time
import commands

from serial import SerialException

#---------------------------------
#           Librerias personales
#---------------------------------

#from Lib_File import *  # importar con los mismos nombres
#from Lib_Rout import *  # importar con los mismos nombres
from Fun_Modbus import *  # importar con los mismos nombres

#-------------------------------------------------------------------------------------
#                                   CONSTANTES
#-------------------------------------------------------------------------------------


SMD_Mensajes = 1    # 0: NO print  1: Print

Puerto_Serial = '/dev/ttyS0'
port = serial.Serial(Puerto_Serial, baudrate=9600, timeout=1)

Status_RX =0

Contador_Dispotivos =   0
N_Dispositivos      =   0
ID_Dispositivos     =   []
Estados_Test_Dispo  =   0

Contador_Espera_resepcion=0;
Max_Espera_resepcion=2;





#--------------------------------------------------------------------------------------

def Tramas_TX():
    global port
    global SMD_Mensajes
    global Status_RX
    #-------------------------------
    #Para dispotitos CCCB
    #-------------------------------
    rele = Get_File(TX_MODBUS) # leer una linea e eliminar <0001:Access granted-E>
    if len(rele)>= 1:

        if SMD_Mensajes: print 'TX:' + rele

        port.write(rele)
        Status_RX=0
        Clear_File(TX_MODBUS)

#---------------------------------------------------------------------------------------

def Tramas_RX():
    global port
    global SMD_Mensajes
    global Puerto_Serial
    global Status_RX

    try :
        #Tx_datos()
        rcv = port.read(250)
        T_rcv = len(rcv)
        if T_rcv >= 1:
            if SMD_Mensajes: print 'Cuantos:' + str(T_rcv)
            print 'RX:' + rcv
            #print 'RX:'
            #Procesar_Datos(rcv)
            Status_RX = 1
        else:
            if SMD_Mensajes: print 'Nada'


    except SerialException:
        while True:
            port = serial.Serial(Puerto_Serial, baudrate=9600, timeout=1)
            break

#---------------------------------------------------------------------------------------
def Control_Canal_Serial():
    while True:
        Tramas_RX()
        Tramas_TX()
        #proceso_Escan_Dispositivos()






#---------------------------------------------------------------------------------------

def proceso_Escan_Dispositivos():
    global N_Dispositivos
    global ID_Dispositivos
    global Contador_Dispotivos
    global Estados_Test_Dispo
    global SMD_Mensajes
    global Contador_Espera_resepcion
    global Max_Espera_resepcion
    global Status_RX

    if Estados_Test_Dispo == 2:
        if SMD_Mensajes: print 'Estado 2: Espera de respuesta del dispotivo'
        if Status_RX == 1:
            Status_RX = 0
            Estados_Test_Dispo = 1
            Contador_Espera_resepcion =0
        else:
            Contador_Espera_resepcion = Contador_Espera_resepcion + 1
            if Contador_Espera_resepcion >= Max_Espera_resepcion:
                Estados_Test_Dispo = 1
                Contador_Espera_resepcion =0



    if Estados_Test_Dispo == 1:
        if SMD_Mensajes: print 'Estado 1: Tes de dispsotivos'

        if Contador_Dispotivos < N_Dispositivos :

            #Trama_Armanda = TRAMA_INIT + ID_Dispositivos[Contador_Dispotivos] + FUN_GET_ID + CUARTETA_DEFAULT + TRAMA_FIN
            Trama_Armanda = TRAMA_INIT + ID_Dispositivos[Contador_Dispotivos] + FUN_DATA_M_USUARIO + CUARTETA_DEFAULT + TRAMA_FIN

            Set_File(TX_MODBUS, Trama_Armanda)
            if SMD_Mensajes: print 'Trama:' + Trama_Armanda
            Contador_Dispotivos = Contador_Dispotivos+1
            Estados_Test_Dispo = 2

        else: # termino de testar los dispsotivos
            Contador_Dispotivos =0
            Estados_Test_Dispo = 1






    if Estados_Test_Dispo == 0:
        if SMD_Mensajes: print 'Estado 0: Actualizar dipositivos de archivos'
        N_Dispositivos, ID_Dispositivos =Get_Dispositivos()
        if SMD_Mensajes:
            print 'N Dispositivos:'+ str(N_Dispositivos)
            print 'ID Dispositivos:'+ str(ID_Dispositivos)
        Estados_Test_Dispo =1






#---------------------------------------------------------------------------------------


Control_Canal_Serial()
#proceso_Escan_Dispositivos()
