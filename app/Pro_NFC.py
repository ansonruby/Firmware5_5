#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Libreria personal para procesar NFC.




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
from lib.Lib_Encryp import *            # importar con los mismos nombres
from lib.Lib_File import *            # importar con los mismos nombres
from lib.Lib_Rout import *            # importar con los mismos nombres
from lib.Lib_Requests_Server import *   #
from lib.Lib_Networks import *   #
from lib.Fun_Dispositivo import *   #
from lib.Fun_Server import *   #
from lib.Fun_Tipo_NFC import *   #
from lib.Fun_Tipo_QR import *   #

#from lib.Verificar_Usuarios import *  # importar con los mismos nombres

#-------------------------------------------------------
# inicio de variable	--------------------------------------

PN_Mensajes = 0     # 0: NO print  1: Print

#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
#                   Deisiones para autorizar con Nfc
#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------

#---------------------------------------------------------
#----       Ruta para que autorise el servidor
#---------------------------------------------------------
def Decision_General(Canal):
    global PN_Mensajes

    #QR_RUT ='NFC'
    T_A = str(int(time.time()*1000.0))  # Tiempo()

    if PN_Mensajes:
        print 'Nuevo------------------------------------'
        print 'Tiempo: ', "%s" % T_A

    # Prepararacion de informacion para tratamiento
    Set_File(COM_BUZZER,'1')       #sonido eliminar si no es necesario
    R_NFC = Get_NFC(Canal)


    if PN_Mensajes:
        print 'NFC: '+ R_NFC


    # -----------------------------------------------------------------------------
    # Decision dependiendo del estado del dispositivo y configuracion de prioridades
    # -----------------------------------------------------------------------------

    Prioridad = Get_File(CONF_AUTORIZACION_NFC).strip()
    #Prioridad = '1'

    # ------- Prioridades de autorizacion ---------------------
    # 0 :   Servidor      -> Dispositivos -> sin counter    F1_17
    # 1 :   Counter       -> Dispositivos -> sin Servidor   F2_0
    # 2 :   Servidor      -> counter      -> Dispositivos   Nuevo
    # 3 :   Counter       -> Servidor     -> Dispositivos   Nuevo
    # ---------------------------------------------------------

    if PN_Mensajes: print 'Prioridad: '+ str(Prioridad)

    #Decision_Dispositivo(R_NFC,T_A)

    if  Prioridad == '0':
        if PN_Mensajes: print 'Prioridad Serv -> Dispo'
        Status_Peticion_Server = Decision_Server(R_NFC,T_A)
        if Status_Peticion_Server != -2:
            if Status_Peticion_Server == -1: # Error en el servidor
                Status_Peticion_Counter = Decision_Dispositivo(R_NFC,T_A)
                if  Status_Peticion_Counter != -2:
                    if  Status_Peticion_Counter == -1:# Error en el  Dispositivo
                        Accion_Torniquete ('Error') # Qr no valido
                else: Accion_Torniquete ('Error') # Qr no valido
        else: Accion_Torniquete ('Error') # Qr no valido
    # ---------------------------------------------------------
    elif  Prioridad == '1':
        if PN_Mensajes: print 'Prioridad Counter -> Dispo'
        Status_Peticion_Counter = Decision_Counter(R_NFC,T_A,Canal)
        if Status_Peticion_Counter != -2:
            if Status_Peticion_Counter == -1: # Error en el counter
                Status_Peticion_Dispo = Decision_Dispositivo(R_NFC,T_A)
                if  Status_Peticion_Dispo != -2:
                    if  Status_Peticion_Dispo == -1:# Error en el  Dispositivo
                        Accion_Torniquete ('Error') # Qr no valido
                else: Accion_Torniquete ('Error') # Qr no valido
        else: Accion_Torniquete ('Error') # Qr no valido
    # ---------------------------------------------------------
    else: Accion_Torniquete ('Error') # no hay prioridad







    """
    flag_Send = Get_File(CONT_SEND_FLAG_PATH)
    #print flag_Send
    if flag_Send == '':
        if PP_Mensajes:
            print ' --Decision Counter--'
        #Decision_Counter(R_Q,T_A)
    else:
        if PP_Mensajes:
            print ' --Decision Dispositivo--'
        Decision_Dispositivo(R_Q,T_A)
    """

    #print 'Desicion:' + str(Decision_Server(R_Q,T_A))
    #print 'Desicion:' + str(Decision_Dispositivo(R_NFC,T_A))
    #print 'Desicion:' + str(Decision_Counter(R_NFC,T_A))





#---------------------------------------------------------
#----       Ruta para que autorise el Dispositivo
#---------------------------------------------------------

def Decision_Dispositivo(NFC, Tiempo_Actual):
    global PN_Mensajes

    if PN_Mensajes: print 'Autorisa el Dispositivo'

    NFC_Md5 = MD5(NFC)
    if PN_Mensajes: print 'MD5: '+ NFC_Md5
    ID = Buscar_ID_NFC(NFC_Md5)
    if PN_Mensajes: print 'ID: '+ str(ID)
    #Pos_linea, Resp, Usuario = Decision_Tipo_NFC(NFC_Md5)
    if ID != -1:
        Pos_linea, Resp =Decision_NFC_Usuarios(ID)#Buscar_acceso_Usuario(ID)
    else:
        Pos_linea   = -1
        Resp        = "Denegado"

    if PN_Mensajes:
        print 'Resp:'+ Resp
        print 'Pos_linea:'+ str(Pos_linea)

    if Resp.find("Denegado") == -1:                           # Entradas/Salidas Autorizadas
        Accion_Torniquete (Resp)

        Guardar_Autorizacion_Usuario_Tipos('NFC', ID, Resp, '0')
        Dato =''
        if      Resp == 'Access granted-E': Dato =  '6.'+ ID + '.' + NFC_Md5 + '.' + Tiempo_Actual + '.11.0.0' + '\n'
        elif    Resp == 'Access granted-S': Dato =  '6.'+ ID + '.' + NFC_Md5 + '.' + Tiempo_Actual + '.11.1.0' + '\n'

        #Dato = Guardar_Autorizacion_General_NFC(Usuario.strip(), Tiempo_Actual, Pos_linea, Resp, '1') # guardar un registro de lo autorizado
        #----desicion a quie envio lo autorizado
        Prioridad = Get_File(CONF_AUTORIZACION_NFC).strip()
        if Prioridad == '0': # solo enviar lo autorizado al servidor
            Enviar_Autorizado_Server(Dato)
        if Prioridad == '1': # solo enviar lo autorizado al counter
            Enviar_Autorizado_Counter(Dato) # envio general


        return 1                                                # funcionamiento con normalidad
    else :                                                      # denegado
        Accion_Torniquete (Resp)
        return 1                                                # funcionamiento con normalidad


    #NOTAS
    # return -1 # No cumple parametros
    # return 1  # funcionamiento con normalidad

#---------------------------------------------------------
def Buscar_ID_NFC(NFC): #mejorar por que podia pasa cualquiera
    NFC = NFC.strip()
    #print NFC
    Usuarios = Get_File(TAB_USER_TIPO_6)
    for linea in Usuarios.split('\n'):
        if linea.count('.') >= 1:
            Vector = linea.split(".")
            #print Vector[1]
            #print NFC == Vector[1]
            #print 'que pasa:'
            #print NFC in Vector[1]
            #if NFC.find(Vector[1])  != -1:
            if NFC in Vector[1] :
                return Vector[0]

    return -1
#---------------------------------------------------------
def Decision_NFC_Usuarios(ID):
    global FTN_Mensajes


    Veri_Impreso = ID #Buscar_NFC(NFC_Md5)
    #print Veri_Impreso
    if Veri_Impreso != -1 :
        Pos_linea,Tipo_IO =Buscar_acceso_Usuario(ID)
        if FTN_Mensajes:
            print 'Exite'
            print Pos_linea
            print Tipo_IO
        if Pos_linea == -1 :    return -1,'Access granted-E'    # esta el usuario pero no tiene registro
        else:
            if Tipo_IO == '0':      # 0: entrada.1: salida .
                return Pos_linea,'Access granted-S'             # registro de entrada otorga salida
            elif Tipo_IO == '1':    # 0: entrada.1: salida .
                return Pos_linea,'Access granted-E'             # registro de entrada otorga Entrada

        #return -1,'Access granted-E', Usuario
    else:
        return -1,'Denegado'

    return -1,'Denegado'



#---------------------------------------------------------
#----       Ruta para que autorise el counter
#---------------------------------------------------------
def Decision_Counter(NFC, Tiempo_Actual,Canal):
    global PN_Mensajes

    if PN_Mensajes: print 'Autorisa el counter'

    #Validacion, QR = Validar_QR(QR)              # Valido y que tipo es?
    #if PN_Mensajes: print 'Tipo QR:' + Validacion
    NFC_Md5 = MD5(NFC)
    if PN_Mensajes: print 'MD5: '+ NFC_Md5


    Direccion_Tiempo = str(Tiempo_Actual) + '.' + str(Canal)
    #------------------------------------------------------------------------------------------------------------

    Respuesta, conteo = Enviar_NFC_Counter('6.'+ NFC_Md5, Direccion_Tiempo)
    if PN_Mensajes: print 'Respuesta: ' + str(Respuesta)


    if "Access granted" in Respuesta:                           # Entradas/Salidas Autorizadas
        Accion_Torniquete (Respuesta)
        # verificar si hay registros del usuario
        Veri_Impreso,Usuario = Buscar_NFC(NFC_Md5)
        Pos_linea,Tipo_IO =Buscar_acceso_NFC(NFC_Md5)
        Guardar_Autorizacion_General_NFC(Usuario.strip(), Tiempo_Actual, Pos_linea, Respuesta, '1') # guardar un registro de lo autorizado
        return 1

    elif Respuesta.find("Access denied") != -1:          # Autorizaciones denegadas
        Accion_Torniquete (Respuesta)
        return 1

    else :                                                      # Sin internet Momentanio o fallo del servidor
        if PN_Mensajes: print 'Sin internet o Fallo del counter'
        return -1


    #NOTAS
    # return -2 #NO tiene tipo de qr valido
    # return -1 #fallo en el counter
    # return 1  # respuesta del servidor valida
    return -2



#---------------------------------------------------------
#----       Ruta para que autorise el servidor
#---------------------------------------------------------
def Decision_Server(Teclado, Tiempo_Actual):
    global PN_Mensajes

    if PN_Mensajes: print 'Autorisa el servidor'

    Ruta            = Get_Rout_server()
    ID_Dispositivo  = Get_ID_Dispositivo()
    if PN_Mensajes: print 'Ruta:' + str(Ruta.strip()) + ', UUID:' + ID_Dispositivo
    #Enviar_Teclado(IP,T_actual,ID,Rut)

    Respuesta = Enviar_Teclado(Ruta.strip(), Tiempo_Actual, ID_Dispositivo, '6.'+Teclado)

    if PN_Mensajes: print 'Respuesta: ' + str(Respuesta)

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
        if PN_Mensajes: print 'Sin internet o Fallo del servidor'
        return -1




    #NOTAS
    # return -2 #NO tiene tipo de qr valido
    # return -1 #sin internet o fallo del servidor
    # return 1  # respuesta del servidor valida
    return -2


#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
#               Acciones en el Actuador (torniquete) y visualizadores
#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
def Accion_Torniquete (Res):
    global PN_Mensajes

    Res=Res.rstrip('\n')            # eliminar caracteres extras
    Res=Res.rstrip('\r')            # eliminar caracteres extras
    if PN_Mensajes: print Res

    if Res == 'Access granted-E':
        if PN_Mensajes: print "L_Access granted-E"
        Set_File(COM_LED , 'Access granted-E')
        Set_File(COM_RELE, 'Access granted-E')

        Set_File(COM_TX_RELE, 'Access granted-E')


    elif Res == 'Access granted-S':
        #if PP_Mensajes: print "Access granted-S"
        Set_File(COM_LED , 'Access granted-S')
        Set_File(COM_RELE, 'Access granted-S')

        Set_File(COM_TX_RELE, 'Access granted-E')

    else :
        if PN_Mensajes: print "Denegado"
        Set_File(COM_LED, 'Error')

        Set_File(COM_TX_RELE, 'Error')



#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
#               Funciones principales para procesamiento de QR
#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
def Get_NFC (Canal):
    if Canal == 0 :   Pal=    Get_File(COM_NFC)
    if Canal == 1 :   Pal=    Get_File(COM_NFC_S1)
    if Canal == 2 :   Pal=    Get_File(COM_NFC_S2)
    #Pal=    Get_File(COM_NFC)
    Pal=Pal.rstrip('\n')
    Pal=Pal.rstrip('\r')
    return Pal
#---------------------------------------------------------
def revicion_NFC ():
    if Get_File(STATUS_NFC) == '1':
        Decision_General(0)
        Clear_File(STATUS_NFC)
    elif Get_File(STATUS_NFC_S1) == '1':
        Decision_General(1)
        Clear_File(STATUS_NFC_S1)
    elif Get_File(STATUS_NFC_S2) == '1':
        Decision_General(2)
        Clear_File(STATUS_NFC_S2)


#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
print 'Ciclo principal para NFC'
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
    revicion_NFC ()
