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

from lib.Lib_File import *  # importar con los mismos nombres
from lib.Lib_Rout import *  # importar con los mismos nombres

#-----------------------------------------------------------
#                       CONSTANTES
#-----------------------------------------------------------

SQ_Mensajes = 1     # 0: NO print  1: Print

Puerto_Serial = '/dev/ttyS0'
port = serial.Serial(Puerto_Serial, baudrate=9600, timeout=1)

QR =''              # guardado de qr valido
QR_antes =''        # QR anterior
Init_QR = ''        # parte inicial de un qr
Fin_QR = ''         # parte Final de un qr

T_Maximo = 7        # timepo maximo para verificar un repetido para tipo  3 o tiket
T_Nuev_QR = 0       # timepo de inicioa de un nuevo qr
T_Repe_QR = 0       # timepo de inicioa de un nuevo qr


def Tx_datos():
    #-------------------------------
    #Para dispotitos CCCB
    #-------------------------------
    rele = Get_File(COM_TX_RELE)
    if len(rele)>= 1:
        port.write(rele)
        Clear_File(COM_TX_RELE)
#---------------------------------------------------------------------------------------
#                                   Funciones para la lectura de QR
#---------------------------------------------------------------------------------------
def No_Valido_QR(x):
    global SQ_Mensajes, QR, QR_antes, T_Nuev_QR, T_Repe_QR, T_Maximo
    QR = x
    if 'Igual' in QR :
        if SQ_Mensajes: print 'Repetido'
        Set_File(STATUS_REPEAT_QR, '2')    # Estado QR repetido
    elif QR != QR_antes:
        QR_antes = QR
        #T_Nuev_QR = time.time()
        if SQ_Mensajes: print 'NO QR: ' + QR
        Guardar_QR()
        Activar_QR()
    else:
        if SQ_Mensajes: print 'Repetido'
        Set_File(STATUS_REPEAT_QR, '2')    # Estado QR repetido


#---------------------------------------------------------------------------------------

def Nueva_Avilitacion_portiempo_y_Tipo():
    global SQ_Mensajes, QR
    #print 'Repe_Nueva habilitacion'
    puntos = QR.count(".")
    #print puntos
    if puntos == 1:
        if SQ_Mensajes: print 'R_Avi Tiket: '+QR
        Set_File(STATUS_QR, '1')
    elif puntos == 3:
        if SQ_Mensajes: print 'R_Avi Tiket: '+QR
        Set_File(STATUS_QR, '1')
    elif puntos == 4:               #para tipo 3
        if SQ_Mensajes: print 'R_Avi Tipo 3: '+QR
        Set_File(STATUS_QR, '1')
    else:
        if SQ_Mensajes: print 'Repetido'
        Set_File(STATUS_REPEAT_QR, '2')

#---------------------------------------------------------------------------------------

def Decision_Qr(x):
    global SQ_Mensajes, QR, QR_antes, T_Nuev_QR, T_Repe_QR, T_Maximo
    #--------- QR repetido
    QR = x
    if QR != QR_antes:
        QR_antes = QR
        T_Nuev_QR = time.time()
        if SQ_Mensajes: print 'Nuevo: ' + QR
        Guardar_QR()
        Activar_QR()
    else:
        #print 'Repetido:' + x + ' , Estado Valido: ' + str(Valido)
        T_Repe_QR = time.time()
        T_transcurido = int(T_Repe_QR-T_Nuev_QR)
        #print 'T_Diferencia: ' + str(T_transcurido)
        if T_transcurido >= T_Maximo :
            T_Nuev_QR = T_Repe_QR = time.time()
            Nueva_Avilitacion_portiempo_y_Tipo()
        else:
            if SQ_Mensajes: print 'Repetido'
            Set_File(STATUS_REPEAT_QR, '2')    # Estado QR repetido

        #print 'T_Nuevo:' + str(T_Nuev_QR) + ' , T_Repetido:' + str(T_Repe_QR) + ', T_Diferencia: ' + str(int(T_Repe_QR-T_Nuev_QR))

#---------------------------------------------------------------------------------------

def Activar_QR():
    Set_File(STATUS_QR, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR

#---------------------------------------------------------------------------------------

def Guardar_QR():
    global QR
    #QRG = QR.replace ("<","")
    #QRG = QRG.replace (">","")
    Clear_File(COM_QR)          # Borrar QR
    Set_File(COM_QR, QR)       # Guardar QR

#---------------------------------------------------------------------------------------

def Parte_Inicial_QR(x):
    global Init_QR, Fin_QR
    Init_QR = x
    Fin_QR  = ''

#---------------------------------------------------------------------------------------

def Parte_Fin_QR(x):
    global Init_QR, Fin_QR
    Fin_QR  = x
    Total = Init_QR + Fin_QR

    if Validar_QR(Total) == 1:
         Decision_Qr(Total)          #QR valido
         Init_QR = Fin_QR = ''















#---------------------------------------------------------------------------------------

def Validar_QR(x):
    TaCadena = len (x)
    Inicio = x[0:1]
    Fin = x[TaCadena-1:TaCadena]
    #print TaCadena
    if TaCadena >= 1:
        if (Inicio == '<' ) and (Fin == '>'):       return 1    #print 'OK' valido y completo
        else:
            if (Inicio == '<' ):                    return 2    #print 'Inicio: ' + Inicio parte inicial de un qr valido
            elif (Fin == '>'):                      return 3    #print 'Fin' + Fin parte final de un qr valido
            else:                                   return -1   #print 'NO' no tine ninguna parte valida
    else:                                           return -2   #print 'NO' no hay cadena

#---------------------------------------------------------------------------------------

def Procesar_Datos(rcv):
    global SQ_Mensajes
    #if SQ_Mensajes: print 'Datos RX:' + rcv
    Lineas = rcv.split('\r')
    for x in Lineas:
        Valido = Validar_QR(x)
        if      Valido == 1:    Decision_Qr(x)          #QR valido
        elif    Valido == 2:    Parte_Inicial_QR(x)     #Inicio QR
        elif    Valido == 3:    Parte_Fin_QR(x)         #Fin QR
        elif    Valido == -1:   No_Valido_QR(x)         #No valido
        #elif    Valido == -2:   print Valido #basio no hay cadena




#---------------------------------------------------------------------------------------

def Datos_Serial():
    global port
    global SQ_Mensajes
    global Puerto_Serial

    while True:
        try :
            Tx_datos()
            rcv = port.read(250)
            T_rcv = len(rcv)
            if T_rcv >= 1:
                #if SQ_Mensajes: print 'Cuantos:' + str(T_rcv)
                Procesar_Datos(rcv)


        except SerialException:
            while True:
                port = serial.Serial(Puerto_Serial, baudrate=9600, timeout=1)
                break
#---------------------------------------------------------------------------------------





















#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------

if SQ_Mensajes: print 'Activo mensajes: ' + str(SQ_Mensajes)
if SQ_Mensajes: print Puerto_Serial
#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------

while 1:
    #---------------------------------------------------------
    #  Lectura de serial
    #---------------------------------------------------------
    Datos_Serial()




"""




Eliminar_antes=0
N_Cade=0
C_armar=''

QR =''
QR_antes =''
Tinicio =0
Tfin =0
Tdiferencia =0
TRepeticion = 2

#---------------------

#---------------------
def Tx_datos():
    #-------------------------------
    #Para dispotitos CCCB
    #-------------------------------
    rele = Get_File(COM_TX_RELE)   #Leer_Estado(38)
    if len(rele)>= 1:
        #
        #print rele
        port.write(rele)
        Clear_File(COM_TX_RELE)          #Borrar(38)
    #-------------------------------

#---------------------
def Tiempo_Repeticiones():
    global SQ_Mensajes
    global Tinicio
    global Tfin
    global Tdiferencia
    global TRepeticion

    global QR
    global QR_antes

    global B_sensor

    Tfin = time.time()
    Tdiferencia = Tfin - Tinicio

    if Tdiferencia >= TRepeticion:
        if SQ_Mensajes: print 'Procesar:'+QR + ' T_Diferencia:'+ str(Tdiferencia)
        QR_antes = QR
        QR = QR.replace ("<","")
        QR = QR.replace (">","")
        Guardar_QR()
        B_sensor = 2

    Tinicio = time.time()
#---------------------

#---------------------
def Leer_datos_SensorQR():

    global Eliminar_antes
    global N_Cade
    global C_armar
    global QR
    global QR_antes
    global B_sensor
    global Tinicio
    global Tfin
    global Tdiferencia
    global TRepeticion
    global port
    global res


    while True:

        try :
            Tx_datos()
            #-----------------------------------------
            #       Analisis de Cadenas recojidas
            #-----------------------------------------
            rcv = port.read(250)
            T_rcv = len(rcv)
            #print T_rcv

            if T_rcv >= 1:

                QRT = rcv.split('\r')
                #print QRT

                for x in QRT:
                    #print 'x Procesando: '+x
                    N_Cade +=1

                    TaCadena = len (x)
                    Inicio = x[0:1]
                    Fin = x[TaCadena-1:TaCadena]

                    if (Inicio == '<' ) and (Fin == '>'):

                        N_Cade=0
                        C_armar=''

                        QR = x
                        Cadena_Valida()


                    else:
                        C_armar=C_armar + x

                        if (C_armar[0:1] == '<' ) and (C_armar[len (C_armar)-1:len (C_armar)] == '>'):

                            QR = C_armar
                            Cadena_Valida()

                            N_Cade=0
                            C_armar=''
                        else:
                            if len(x) >=2:
                                if (Inicio == '<' ) or (Fin == '>'):
                                    a=0
                                    #print 'pertenese a un qr valido'
                                else:
                                    #print 'NO cumple parametros'
                                    #print 'X: '+x
                                    QR = x
                                    if QR != QR_antes:
                                        #print 'X QR: '+QR
                                        QR_antes = QR
                                        #print 'que pasa'

                                        if QR.find("Igual") != -1:
                                            aqr = Get_File(COM_QR)  #Leer_Estado(7) #QR
                                            aqr= aqr.strip()
                                            puntos = aqr.count(".")
                                            #print puntos

                                            if puntos == 3:
                                                Set_File(STATUS_QR, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
                                                print 'sin tiempo3'
                                            #elif puntos == 4:               #para tipo 3
                                            #    Set_File(STATUS_QR, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
                                            else:
                                                Set_File(STATUS_REPEAT_QR, '2')    #Escrivir_Estados('2',11) # Estado QR repetido
                                                print 'QR YA: ' +QR
                                                print 'sin tiempo3'
                                            #Escrivir_Estados('2',11) # Estado QR repetido
                                            #print "Repetido"

                                        else:

                                            Guardar_QR()
                                            B_sensor = 2
                                    else:

                                        if QR.find("Igual") != -1:
                                            aqr = Get_File(COM_QR)  #Leer_Estado(7) #QR
                                            aqr= aqr.strip()
                                            puntos = aqr.count(".")
                                            #print puntos
                                            if puntos == 3:
                                                Set_File(STATUS_QR, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
                                                print 'sin tiempo3'
                                            elif puntos == 4:               #para tipo 3
                                                #print 'OK QR Tipo 3: '+QR
                                                Set_File(STATUS_QR, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
                                                print 'sin tiempo3'



                #----------------------------------
                #           fin del for
                N_Cade = 0

            else:

                #       Descartar por tiempo espirado
                Eliminar_antes +=1
                if Eliminar_antes >=5:
                    #print 'Borado de cadenas y puesta en zero'
                    Eliminar_antes=0
                    N_Cade=0
                    C_armar=''
                    B_sensor = 0

                #print 'salida del while'
                break

        except SerialException:
            #print 'algo paso'
            #port.close()
            while True:
                port = serial.Serial(Puerto_Serial, baudrate=9600, timeout=1)
                break

    #---------------------------------------
    #       fin de analisis de cadena
    #---------------------------------------



"""
