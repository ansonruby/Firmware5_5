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
import serial
import os, time
import commands

from serial import SerialException

from Lib_File import *  # importar con los mismos nombres
from Lib_Rout import *  # importar con los mismos nombres


"""
import lib.Control_Archivos  as Ca

Leer                    = Ca.Leer_Led
Borrar                  = Ca.Borrar_Archivo
Escrivir_Estados        = Ca.Escrivir_Estados
Escrivir                = Ca.Escrivir_Archivo
Leer_Estado             = Ca.Leer_Estado
"""

SQ_Mensajes = 1     # 0: NO print  1: Print

Puerto_Serial = '/dev/ttyS0'
if SQ_Mensajes: print 'Activo mensajes: ' + str(SQ_Mensajes)
if SQ_Mensajes: print Puerto_Serial

port = serial.Serial(Puerto_Serial, baudrate=9600, timeout=1)


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
def Guardar_QR():
    global QR
    Clear_File(COM_QR)          #Borrar(7)               # Borrar QR
    Set_File(COM_QR, QR)        #Escrivir(QR,7)          # Guardar QR
    Set_File(STATUS_QR, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR

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
def Cadena_Valida():
    global SQ_Mensajes
    global QR
    global QR_antes

    if QR != QR_antes:
        #print 'OK QR: '+QR
        Tiempo_Repeticiones()
    else:
        #Log_QR()
        # si la foma es la del tiiqued proceesar denuevo
        puntos = QR.count(".")
        #print puntos
        if puntos == 3:
            if SQ_Mensajes: print 'OK QR Tres puntos: '+QR
            Set_File(STATUS_QR, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
        elif puntos == 4:               #para tipo 3
            if SQ_Mensajes: print 'OK QR Tipo 3: '+QR
            Set_File(STATUS_QR, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
        else:
            Set_File(STATUS_REPEAT_QR, '2')    #Escrivir_Estados('2',11) # Estado QR repetido
            if SQ_Mensajes: print 'QR Repetido: ' + QR


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


while 1:

    Leer_datos_SensorQR()
