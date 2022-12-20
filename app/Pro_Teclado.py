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

from lib.Lib_File import *              # importar con los mismos nombres
from lib.Lib_Rout import *              # importar con los mismos nombres
from lib.Lib_Requests_Server import *   #
from lib.Lib_Networks import *          #
from lib.Fun_Dispositivo import *       #
from lib.Fun_Server import *            #
from lib.Fun_Tipo_QR import *           #
from lib.Lib_Encryp import *           #

#-------------------------------------------------------
# inicio de variable	--------------------------------

PT_Mensajes = 0     # 0: NO print  1: Print

#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
#                   Deisiones para autorizar por teclado
#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------

#---------------------------------------------------------
#----
#---------------------------------------------------------
def Decision_General(Canal):
    global PT_Mensajes


    T_A = str(int(time.time()*1000.0))  # Tiempo()

    if PT_Mensajes:
        print 'Nuevo------------------------------------'
        print 'Tiempo: ', "%s" % T_A

    # Prepararacion de informacion para tratamiento
    Set_File(COM_BUZZER,'1')       #sonido eliminar si no es necesario
    R_Teclas = Get_Teclas(Canal)

    if PT_Mensajes:
        print 'Digitado: '+ R_Teclas

    # -----------------------------------------------------------------------------
    # Decision dependiendo del estado del dispositivo y configuracion de prioridades
    # -----------------------------------------------------------------------------

    Prioridad = Get_File(CONF_AUTORIZACION_TECLADO).strip()

    # ------- Prioridades de autorizacion ---------------------
    # 0 :   Servidor      -> Dispositivos -> sin counter    F1_17
    # 1 :   Counter       -> Dispositivos -> sin Servidor   offLine
    # 2 :   Servidor      -> counter      -> Dispositivos   Nuevo
    # 3 :   Counter       -> Servidor     -> Dispositivos   Nuevo
    # ---------------------------------------------------------
    if  Prioridad == '0':
        if PT_Mensajes: print 'Prioridad Serv -> Dispo'
        Status_Peticion_Server = Decision_Server(R_Teclas, T_A)
        if Status_Peticion_Server != -2:
            if Status_Peticion_Server == -1: # Error en el servidor
                Status_Peticion_Dispo = Decision_Dispositivo(R_Teclas,T_A)
                if  Status_Peticion_Dispo != -2:
                    if  Status_Peticion_Dispo == -1:# Error en el  Dispositivo
                        Accion_Torniquete ('Error') # Qr no valido
                else: Accion_Torniquete ('Error') # Qr no valido
        else: Accion_Torniquete ('Error') # Qr no valido

        # if  Status_Peticion_Server == -1:# Error en el  Dispositivo
        # Accion_Torniquete ('Error') # Qr no valido

    # ---------------------------------------------------------
    elif  Prioridad == '1':
        if PT_Mensajes: print 'Prioridad Counter -> Dispo'
        Status_Peticion_Counter = Decision_Counter(R_Teclas,T_A,Canal)
        if Status_Peticion_Counter != -2:
            if Status_Peticion_Counter == -1: # Error en el counter
                Status_Peticion_Dispo = Decision_Dispositivo(R_Teclas,T_A)
                if  Status_Peticion_Dispo != -2:
                    if  Status_Peticion_Dispo == -1:# Error en el  Dispositivo
                        Accion_Torniquete ('Error') # Qr no valido
                else: Accion_Torniquete ('Error') # Qr no valido
        else: Accion_Torniquete ('Error') # Qr no valido
        # Decision_Counter(R_Teclas, T_A)

    # ---------------------------------------------------------
    elif  Prioridad == '2':
        if PT_Mensajes: print 'Prioridad Serv -> counter -> Dispo'
        Accion_Torniquete ('Error') # no hay prioridad

    # ---------------------------------------------------------
    elif  Prioridad == '3':
        if PT_Mensajes: print 'Prioridad counter -> Serv -> Dispo'
        Accion_Torniquete ('Error') # no hay prioridad

    # ---------------------------------------------------------
    else: Accion_Torniquete ('Error') # no hay prioridad


    #print 'Desicion:' + str(Decision_Server(R_Q,T_A))
    #print 'Desicion:' + str(Decision_Dispositivo(R_Q,T_A))
    #print 'Desicion:' + str(Decision_Counter(R_Q,T_A))

#---------------------------------------------------------
#----       Ruta para que autorise el servidor
#---------------------------------------------------------
def Decision_Server(Teclado, Tiempo_Actual):
    global PT_Mensajes

    if PT_Mensajes: print 'Autorisa el servidor'

    Ruta            = Get_Rout_server()
    ID_Dispositivo  = Get_ID_Dispositivo()
    if PT_Mensajes: print 'Ruta:' + str(Ruta.strip()) + ', UUID:' + ID_Dispositivo
    #Enviar_Teclado(IP,T_actual,ID,Rut)
    Respuesta = Enviar_Teclado(Ruta.strip(), Tiempo_Actual, ID_Dispositivo, Teclado)

    if PT_Mensajes: print 'Respuesta: ' + str(Respuesta)

    if Respuesta.find("Error") == -1:                           # Entradas/Salidas Autorizadas
        Accion_Torniquete (Respuesta)
        # verificar si hay registros del usuario
        #Pos_linea = Buscar_Autorizados_ID_Tipo_1(QR)
        #Guardar_Autorizacion_Tipo_1(QR, Tiempo_Actual, Pos_linea, Respuesta, '1') # status internet en 1
        return 1                                                # funcionamiento con normalidad
    elif Respuesta.find("Error :Access denied") != -1:          # Autorizaciones denegadas
        Accion_Torniquete (Respuesta)
        return 1
    else :                                                      # Sin internet Momentanio o fallo del servidor
        if PT_Mensajes: print 'Sin internet o Fallo del servidor'
        return -1



    #NOTAS
    # return -2 #NO tiene tipo de qr valido
    # return -1 #sin internet o fallo del servidor
    # return 1  # respuesta del servidor valida
    return -2

#---------------------------------------------------------
#----       Ruta para que autorise el counter
#---------------------------------------------------------
def Decision_Counter(TECLADO, Tiempo_Actual,Canal):
    TCL_ENCR=MD5(TECLADO)
    Direccion_Tiempo = str(Tiempo_Actual) + '.' + str(Canal)

    Respuesta, conteo = Enviar_QR_Counter("."+TCL_ENCR, Direccion_Tiempo)
    if PT_Mensajes: print 'Respuesta: ' + str(Respuesta)
    if "Access granted" in Respuesta:                           # Entradas/Salidas Autorizadas
        Accion_Torniquete (Respuesta)
        # verificar si hay registros del usuario
        Pos_linea, Tipo_IO = Buscar_acceso_Tipo1(TCL_ENCR)
        Guardar_Autorizacion_General_Tipo_1("."+TCL_ENCR, Tiempo_Actual, Pos_linea, Respuesta, '1') # status internet en 1
        return 1

    elif Respuesta.find("Access denied") != -1:          # Autorizaciones denegadas
        Accion_Torniquete (Respuesta)
        return 1

    else :                                                      # Sin internet Momentanio o fallo del servidor
        if PT_Mensajes: print 'Sin internet o Fallo del counter'
        return -1
#---------------------------------------------------------
#----       Ruta para que autorise el Dispositivo
#---------------------------------------------------------
def Decision_Dispositivo(TECLADO, Tiempo_Actual):
    global PT_Mensajes

    if PT_Mensajes: print 'Autorisa el Dispositivo'

    TCL_ENCR=MD5(TECLADO)
    if PT_Mensajes: print 'MD5: '+str(TCL_ENCR)

    Pos_linea, Resp = Decision_PIN(TCL_ENCR)
    if PT_Mensajes:
        print 'Resp:'+ Resp
        print 'Pos_linea:'+ str(Pos_linea)

    if Resp.find("Denegado") == -1:
        Accion_Torniquete (Resp)
        Guardar_Autorizacion_Usuario_Tipos('TECLADO', Buscar_PIN(TCL_ENCR), Resp, '0')
        Dato =''
        if      Resp == 'Access granted-E': Dato =  '.' + TCL_ENCR + '.' + Tiempo_Actual + '.2.0.0' + '\n'
        elif    Resp == 'Access granted-S': Dato =  '.' + TCL_ENCR + '.' + Tiempo_Actual + '.2.1.0' + '\n'
        #Dato = Guardar_Autorizacion_General_Tipo_1("."+TCL_ENCR, Tiempo_Actual, Pos_linea, Resp, '1') # guardar un registro de lo autorizado
        # ----desicion a quie envio lo autorizado
        Prioridad = Get_File(CONF_AUTORIZACION_TECLADO).strip()
        if Prioridad == '0': # solo enviar lo autorizado al servidor
            Enviar_Autorizado_Server(Dato) # envio general
        if Prioridad == '1': # solo enviar lo autorizado al counter
            Enviar_Autorizado_Counter(Dato) # envio general

        return 1                                                # funcionamiento con normalidad
    else :                                                      # denegado
        Accion_Torniquete (Resp)
        return 1                                                # funcionamiento con normalidad
#------------------------------------------------------------------------------------------------------------

def Decision_PIN(TECLADO):
    global PT_Mensajes

    ID= TECLADO.strip()
    #if PT_Mensajes: print ID
    ID_1 = Buscar_PIN(ID)
    if PT_Mensajes: print 'ID:'+ID_1
    if ID_1 != -1:
        #print 'verificar tipo de autorizacion'
        #Pos_linea,Tipo_IO =Buscar_acceso_Tipo1(ID)
        Pos_linea, Tipo_IO = Buscar_acceso_Usuario(ID_1)
        if Pos_linea == -1 :    return -1,'Access granted-E'    # esta el usuario pero no tiene registro
        else:
            if Tipo_IO == '0':      # 0: entrada.1: salida .
                return Pos_linea,'Access granted-S'             # registro de entrada otorga salida
            elif Tipo_IO == '1':    # 0: entrada.1: salida .
                return Pos_linea,'Access granted-E'             # registro de entrada otorga Entrada

        return -1,'Denegado'
    else:
        return -1,'Denegado'

def Buscar_PIN(ID_1):  # se puede mejorar la busqueda (busqueda binaria) si la lista esta ordenada
    Usuarios = Get_File(TAB_USER_TIPO_1)
    for linea in Usuarios.split('\n'):
        #print linea.count('.')
        if linea.count('.') >=1:
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")
            # print s2[1]
            if 	ID_1 ==	s2[1]:
                #print 'existe el usuario'
                return s2[0]
    return -1
"""
def Buscar_acceso_Tipo1(ID_1):
    Usuarios = Get_File(TAB_AUTO_TIPO_1)
    Pos_linea=1  # comnesae en 1 para convenzar la linea cero
    for linea in Usuarios.split('\n'):
        if linea.count('.') >=1:
            #print linea
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")
            if 	ID_1 ==	s2[1]:      return Pos_linea, s2[4] # retorno el estado y linea del usuarios
        Pos_linea= 1 + Pos_linea
    return -1,-1
"""
#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
#               Acciones en el Actuador (torniquete) y visualizadores
#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
def Accion_Torniquete (Res):
    global PT_Mensajes

    Res=Res.rstrip('\n')            # eliminar caracteres extras
    Res=Res.rstrip('\r')            # eliminar caracteres extras

    if Res == 'Access granted-E':
        #if PT_Mensajes: print "Access granted-E"
        Set_File(COM_LED , 'Access granted-E')
        Set_File(COM_RELE, 'Access granted-E')

        Set_File(COM_TX_RELE, 'Access granted-E')

    elif Res == 'Access granted-S':
        #if PT_Mensajes: print "Access granted-S"
        Set_File(COM_LED , 'Access granted-S')
        Set_File(COM_RELE, 'Access granted-S')

        Set_File(COM_TX_RELE, 'Access granted-E')

    else :
        #if PT_Mensajes: print "Denegado"
        Set_File(COM_LED, 'Error')

        Set_File(COM_TX_RELE, 'Error')



def Get_Teclas(Canal):
    if Canal == 0 :   Pal=    Get_File(COM_TECLADO)
    if Canal == 1 :   Pal=    Get_File(COM_TECLADO_S1)
    if Canal == 2 :   Pal=    Get_File(COM_TECLADO_S2)
    Pal=Pal.rstrip('\n')
    Pal=Pal.rstrip('\r')
    return Pal
#---------------------------------------------------------------------------------------
def revicion_Teclado ():
    if Get_File(STATUS_TECLADO) == '1':
        Decision_General(0)
        Clear_File(STATUS_TECLADO)
    elif Get_File(STATUS_TECLADO_S1) == '1':
        Decision_General(1)
        Clear_File(STATUS_TECLADO_S1)
    elif Get_File(STATUS_TECLADO_S2) == '1':
        Decision_General(2)
        Clear_File(STATUS_TECLADO_S2)


#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
if PT_Mensajes: print 'Ciclo principal lectura Teclado'
Set_File(COM_LED, '0')
#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------

while 1:
    #---------------------------------------------------------
    #  Proceso 0: Tiempo de espera para disminuir proceso
    #---------------------------------------------------------
    time.sleep(0.05)
    #---------------------------------------------------------
    # Proceso 4: Procesamiento del QR
    #---------------------------------------------------------
    revicion_Teclado ()
