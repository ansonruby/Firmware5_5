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

PP_Mensajes = 1     # 0: NO print  1: Print


#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
#                   Deisiones para autorizar el Qr
#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------

#---------------------------------------------------------
#----       Ruta para que autorise el servidor
#---------------------------------------------------------
def Decision_General(Canal):
    global PP_Mensajes

    QR_RUT ='QR'
    T_A = str(int(time.time()*1000.0))  # Tiempo()

    if PP_Mensajes:
        print 'Nuevo------------------------------------'
        print 'Tiempo: ', "%s" % T_A

    # Prepararacion de informacion para tratamiento
    Set_File(COM_BUZZER,'1')       #sonido eliminar si no es necesario
    R_Q = Get_QR(Canal)

    if PP_Mensajes:
        print 'QR: '+ R_Q

    # -----------------------------------------------------------------------------
    # Decision dependiendo del estado del dispositivo y configuracion de prioridades
    # -----------------------------------------------------------------------------

    Prioridad = Get_File(CONF_AUTORIZACION_QR).strip()

    # ------- Prioridades de autorizacion ---------------------
    # 0 :   Servidor      -> Dispositivos -> sin counter    F1_17
    # 1 :   Counter       -> Dispositivos -> sin Servidor   F2_0
    # 2 :   Servidor      -> counter      -> Dispositivos   Nuevo
    # 3 :   Counter       -> Servidor     -> Dispositivos   Nuevo
    # ---------------------------------------------------------
    if PP_Mensajes: print Prioridad


    if  Prioridad == '0':
        if PP_Mensajes: print 'Prioridad Serv -> Dispo'
        Status_Peticion_Server = Decision_Server(R_Q,T_A)
        if Status_Peticion_Server != -2:
            if Status_Peticion_Server == -1: # Error en el servidor
                Status_Peticion_Counter = Decision_Dispositivo(R_Q,T_A)
                if  Status_Peticion_Counter != -2:
                    if  Status_Peticion_Counter == -1:# Error en el  Dispositivo
                        Accion_Torniquete ('Error') # Qr no valido
                else: Accion_Torniquete ('Error') # Qr no valido
        else: Accion_Torniquete ('Error') # Qr no valido
    # ---------------------------------------------------------
    elif  Prioridad == '1':
        if PP_Mensajes: print 'Prioridad Counter -> Dispo'
        Status_Peticion_Counter = Decision_Counter(R_Q,T_A,Canal)
        if Status_Peticion_Counter != -2:
            if Status_Peticion_Counter == -1: # Error en el counter
                Status_Peticion_Dispo = Decision_Dispositivo(R_Q,T_A)
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
    #print 'Desicion:' + str(Decision_Dispositivo(R_Q,T_A))
    #print 'Desicion:' + str(Decision_Counter(R_Q,T_A))

#---------------------------------------------------------
#----       Ruta para que autorise el servidor
#---------------------------------------------------------
def Decision_Server(QR, Tiempo_Actual):
    global PP_Mensajes

    if PP_Mensajes: print 'Autorisa el servidor'

    Validacion, QR = Validar_QR(QR)              # Valido y que tipo es?
    if PP_Mensajes: print 'Tipo QR:' + Validacion
    #------------------------------------------------------------------------------------------------------------
    if  Validacion == 'T1_1': #falta enviar al counter
        Veri_Impreso = Buscar_Impresos_Tipo_1_1(QR)
        if Veri_Impreso == 0 :

            Ruta            = Get_Rout_server()
            ID_Dispositivo  = Get_ID_Dispositivo()
            if PP_Mensajes: print 'Ruta:' + str(Ruta.strip()) + ', UUID:' + ID_Dispositivo
            QR2 = QR.replace('-',"")
            Respuesta = Enviar_QR(Ruta.strip(),Tiempo_Actual,ID_Dispositivo,QR2)

            if PP_Mensajes: print 'Respuesta: ' + str(Respuesta)

            if Respuesta.find("Error") == -1:                           # Entradas/Salidas Autorizadas
                Accion_Torniquete (Respuesta)
                Add_Line_End(TAB_USER_TIPO_1_1,QR+'\n')                 # guarda por un solo uso

                return 1                                                # funcionamiento con normalidad
            elif Respuesta.find("Error :Access denied") != -1:          # Autorizaciones denegadas
                Accion_Torniquete (Respuesta)
                return 1
            else :                                                      # Sin internet Momentanio o fallo del servidor
                if PP_Mensajes: print 'Sin internet o Fallo del servidor'
                return -1
        else:
            Accion_Torniquete ('Denegado')
            return 1                                                # funcionamiento con normalidad
    #------------------------------------------------------------------------------------------------------------
    if  Validacion == 'T1':
        Ruta            = Get_Rout_server()
        ID_Dispositivo  = Get_ID_Dispositivo()
        if PP_Mensajes: print 'Ruta:' + str(Ruta.strip()) + ', UUID:' + ID_Dispositivo

        Respuesta = Enviar_QR(Ruta.strip(),Tiempo_Actual,ID_Dispositivo,QR)

        if PP_Mensajes: print 'Respuesta: ' + str(Respuesta)

        if Respuesta.find("Error") == -1:                           # Entradas/Salidas Autorizadas
            Accion_Torniquete (Respuesta)
            # verificar si hay registros del usuario
            #print Respuesta
            Guardar_Autorizacion_Usuario_Tipos('T1', QR, Respuesta, '1')

            #Pos_linea = Buscar_Autorizados_ID_Tipo_1(QR)
            #Guardar_Autorizacion_General_Tipo_1(QR, Tiempo_Actual, Pos_linea, Respuesta, '1') # status internet en 1

            return 1                                                # funcionamiento con normalidad
        elif Respuesta.find("Error :Access denied") != -1:          # Autorizaciones denegadas
            Accion_Torniquete (Respuesta)
            return 1
        else :                                                      # Sin internet Momentanio o fallo del servidor
            if PP_Mensajes: print 'Sin internet o Fallo del servidor'
            return -1
    #------------------------------------------------------------------------------------------------------------
    elif  Validacion == 'T2':
        Ruta            = Get_Rout_server()
        ID_Dispositivo  = Get_ID_Dispositivo()
        if PP_Mensajes: print 'Ruta:' + str(Ruta.strip()) + ', UUID:' + ID_Dispositivo

        Respuesta = Enviar_QR(Ruta.strip(),Tiempo_Actual,ID_Dispositivo,QR)

        if PP_Mensajes: print 'Respuesta: ' + str(Respuesta)

        if Respuesta.find("Error") == -1:                           # Entradas/Salidas Autorizadas
            Accion_Torniquete (Respuesta)
            # verificar si hay registros del usuario
            Pos_linea = Buscar_Autorizados_ID_Tipo_2(QR)
            Guardar_Autorizacion_General_Tipo_2(QR, Tiempo_Actual, Pos_linea, Respuesta, '1') # status internet en 1
            return 1                                                # funcionamiento con normalidad
        elif Respuesta.find("Error :Access denied") != -1:          # Autorizaciones denegadas
            Accion_Torniquete (Respuesta)
            return 1
        else :                                                      # Sin internet Momentanio o fallo del servidor
            if PP_Mensajes: print 'Sin internet o Fallo del servidor'
            return -1
    #------------------------------------------------------------------------------------------------------------
    elif  Validacion == 'T2_1':

        Ruta            = Get_Rout_server()
        ID_Dispositivo  = Get_ID_Dispositivo()
        if PP_Mensajes: print 'Ruta:' + str(Ruta.strip()) + ', UUID:' + ID_Dispositivo

        Respuesta = Enviar_QR(Ruta.strip(),Tiempo_Actual,ID_Dispositivo,QR)

        if PP_Mensajes: print 'Respuesta: ' + str(Respuesta)

        if Respuesta.find("Error") == -1:                           # Entradas/Salidas Autorizadas
            Accion_Torniquete (Respuesta)
            # verificar si hay registros del usuario
            Pos_linea = Buscar_Autorizados_ID_Tipo_2_1(QR)
            Guardar_Autorizacion_General_Tipo_2_1(QR, Tiempo_Actual, Pos_linea, Respuesta, '1') # status internet en 1
            return 1                                                # funcionamiento con normalidad
        elif Respuesta.find("Error :Access denied") != -1:          # Autorizaciones denegadas
            Accion_Torniquete (Respuesta)
            return 1
        else :                                                      # Sin internet Momentanio o fallo del servidor
            if PP_Mensajes: print 'Sin internet o Fallo del servidor'
            return -1
    #------------------------------------------------------------------------------------------------------------
    elif  Validacion == 'T3': # pemdiente de integracion

        Ruta            = Get_Rout_server()
        ID_Dispositivo  = Get_ID_Dispositivo()
        if PP_Mensajes: print 'Ruta:' + str(Ruta.strip()) + ', UUID:' + ID_Dispositivo

        Respuesta = Enviar_QR(Ruta.strip(),Tiempo_Actual,ID_Dispositivo,QR)

        if PP_Mensajes: print 'Respuesta: ' + str(Respuesta)

        if Respuesta.find("Error") == -1:                           # Entradas/Salidas Autorizadas
            Accion_Torniquete (Respuesta)
            # verificar si hay registros del usuario
            Pos_linea = Buscar_Autorizados_ID_Tipo3(QR)
            Guardar_Autorizacion_Tipo3(QR, Tiempo_Actual, Pos_linea, Respuesta, '1') # status internet en 1
            return 1                                                # funcionamiento con normalidad
        elif Respuesta.find("Error :Access denied") != -1:          # Autorizaciones denegadas
            Accion_Torniquete (Respuesta)
            return 1
        else :                                                      # Sin internet Momentanio o fallo del servidor
            if PP_Mensajes: print 'Sin internet o Fallo del servidor'
            return -1
    #------------------------------------------------------------------------------------------------------------
    else: #para formatos que no son farmatos fusepong
        Ruta            = Get_Rout_server()
        ID_Dispositivo  = Get_ID_Dispositivo()
        if PP_Mensajes: print 'Ruta:' + str(Ruta.strip()) + ', UUID:' + ID_Dispositivo

        Respuesta = Enviar_QR(Ruta.strip(),Tiempo_Actual,ID_Dispositivo,QR)

        if PP_Mensajes: print 'Respuesta: ' + str(Respuesta)

        if Respuesta.find("Error") == -1:                           # Entradas/Salidas Autorizadas
            Accion_Torniquete (Respuesta)
            # verificar si hay registros del usuario
            Pos_linea = Buscar_Autorizados_ID_Tipo1(QR)
            Guardar_Autorizacion_Tipo_1(QR, Tiempo_Actual, Pos_linea, Respuesta, '1') # status internet en 1
            return 1                                                # funcionamiento con normalidad
        elif Respuesta.find("Error :Access denied") != -1:          # Autorizaciones denegadas
            Accion_Torniquete (Respuesta)
            return 1
        else :                                                      # Sin internet Momentanio o fallo del servidor
            if PP_Mensajes: print 'Sin internet o Fallo del servidor'
            return -1

    #NOTAS
    # return -2     # NO tiene tipo de qr valido
    # return -1     # sin internet o fallo del servidor
    # return 1      # respuesta del servidor valida
    return -2

#---------------------------------------------------------
#----       Ruta para que autorise el counter
#---------------------------------------------------------
def Decision_Counter(QR, Tiempo_Actual,Canal):
    global PP_Mensajes

    if PP_Mensajes: print 'Autorisa el counter'

    Validacion, QR = Validar_QR(QR)              # Valido y que tipo es?
    if PP_Mensajes: print 'Tipo QR:' + Validacion

    Direccion_Tiempo = str(Tiempo_Actual) + '.' + str(Canal)
    #------------------------------------------------------------------------------------------------------------
    if  Validacion == 'T1': #falta enviar al counter
        Respuesta, conteo = Enviar_QR_Counter(QR, Direccion_Tiempo)
        if PP_Mensajes: print 'Respuesta: ' + str(Respuesta)
        if "Access granted" in Respuesta:                           # Entradas/Salidas Autorizadas
            Accion_Torniquete (Respuesta)
            # verificar si hay registros del usuario
            Pos_linea = Buscar_Autorizados_ID_Tipo_1(QR)
            Guardar_Autorizacion_General_Tipo_1(QR, Tiempo_Actual, Pos_linea, Respuesta, '1') # status internet en 1
            return 1

        elif Respuesta.find("Access denied") != -1:          # Autorizaciones denegadas
            Accion_Torniquete (Respuesta)
            return 1

        else :                                                      # Sin internet Momentanio o fallo del servidor
            if PP_Mensajes: print 'Sin internet o Fallo del counter'
            return -1
    #------------------------------------------------------------------------------------------------------------
    if  Validacion == 'T2': #falta enviar al counter
        Respuesta, conteo = Enviar_QR_Counter(QR, Direccion_Tiempo)
        if PP_Mensajes: print 'Respuesta: ' + str(Respuesta)
        if "Access granted" in Respuesta:                           # Entradas/Salidas Autorizadas
            Accion_Torniquete (Respuesta)
            # verificar si hay registros del usuario
            Pos_linea = Buscar_Autorizados_ID_Tipo_2(QR)
            Guardar_Autorizacion_General_Tipo_2(QR, Tiempo_Actual, Pos_linea, Respuesta, '1') # status internet en 1
            return 1

        elif Respuesta.find("Access denied") != -1:          # Autorizaciones denegadas
            Accion_Torniquete (Respuesta)
            return 1

        else :                                                      # Sin internet Momentanio o fallo del servidor
            if PP_Mensajes: print 'Sin internet o Fallo del counter'
            return -1
    #------------------------------------------------------------------------------------------------------------
    if  Validacion == 'T2_1': #falta enviar al counter
        Respuesta, conteo = Enviar_QR_Counter(QR, Direccion_Tiempo)
        if PP_Mensajes: print 'Respuesta: ' + str(Respuesta)
        if "Access granted" in Respuesta:                           # Entradas/Salidas Autorizadas
            Accion_Torniquete (Respuesta)
            # verificar si hay registros del usuario
            Pos_linea = Buscar_Autorizados_ID_Tipo_2(QR)
            Guardar_Autorizacion_General_Tipo_2(QR, Tiempo_Actual, Pos_linea, Respuesta, '1') # status internet en 1
            return 1

        elif Respuesta.find("Access denied") != -1:          # Autorizaciones denegadas
            Accion_Torniquete (Respuesta)
            return 1

        else :                                                      # Sin internet Momentanio o fallo del servidor
            if PP_Mensajes: print 'Sin internet o Fallo del counter'
            return -1
    #------------------------------------------------------------------------------------------------------------
    if  Validacion == 'T3': #falta enviar al counter
        if Ventana_tiempo_Tipo_3(QR, Tiempo_Actual) == 1:
            Respuesta, conteo = Enviar_QR_Counter(QR, Direccion_Tiempo)
            if PP_Mensajes: print 'Respuesta: ' + str(Respuesta)
            if "Access granted" in Respuesta:                           # Entradas/Salidas Autorizadas
                if conteo != "-1":
                    Registro = QR + "." + Tiempo_Actual + ".1.0.1." + conteo
                    Accion_Torniquete (Respuesta)
                    Guardar_Autorizacion_Tipo_3(Registro)   # Guardado interno
                    return 1                                # funcionamiento con normalidad
                else:
                    Accion_Torniquete('Denegado')   #------- es correcto
                    return 1

            elif Respuesta.find("Access denied") != -1:          # Autorizaciones denegadas
                Accion_Torniquete (Respuesta)
                return 1

            else :                                                      # Sin internet Momentanio o fallo del servidor
                if PP_Mensajes: print 'Sin internet o Fallo del counter'
                return -1

        else:
            if PP_Mensajes:    print 'Tiempo vencido:'
            Accion_Torniquete('Denegado')
            return 1

    #NOTAS
    # return -2 #NO tiene tipo de qr valido
    # return -1 #fallo en el counter
    # return 1  # respuesta del servidor valida
    return -2

#---------------------------------------------------------
#----       Ruta para que autorise el maestro Dispositivo
#---------------------------------------------------------
def Decision_Maestro_dispositivo(QR, Tiempo_Actual):
    print 'Autorisa el Maestro dispositivo'

#---------------------------------------------------------
#----       Ruta para que autorise el Dispositivo
#---------------------------------------------------------
def Decision_Dispositivo(QR, Tiempo_Actual):
    global PP_Mensajes

    if PP_Mensajes: print 'Autorisa el Dispositivo'

    Validacion, QR = Validar_QR(QR)              # Valido y que tipo es?

    if PP_Mensajes: print 'Tipo QR:' + Validacion

    #------------------------------------------------------------------------------------------------------------
    if  Validacion == 'T1_1': #falta enviar al counter
        Pos_linea, Resp = Decision_Tipo_1_1(QR)
        if PP_Mensajes:
            print 'Resp:'+ Resp
            print 'Pos_linea:'+ str(Pos_linea)

        if Resp.find("Denegado") == -1:                           # Entradas/Salidas Autorizadas
            Accion_Torniquete (Resp)


            Dato = Guardar_Autorizacion_General_Tipo_1_1(QR, Tiempo_Actual, Pos_linea, Resp, '1') # guardar un registro de lo autorizado
            #----desicion a quie envio lo autorizado
            Prioridad = Get_File(CONF_AUTORIZACION_QR).strip()
            if Prioridad == '0': # solo enviar lo autorizado al servidor
                Enviar_Autorizado_Server(Dato) # envio general
            if Prioridad == '1': # solo enviar lo autorizado al counter
                Enviar_Autorizado_Counter(Dato) # envio general

            return 1                                                # funcionamiento con normalidad
        else :                                                      # denegado
            Accion_Torniquete (Resp)
            return 1                                                # funcionamiento con normalidad
    #------------------------------------------------------------------------------------------------------------
    if  Validacion == 'T1': #falta enviar al counter

        Pos_linea, Resp = Decision_Tipo_1(QR)
        if PP_Mensajes:
            print 'Resp:'+ Resp
            print 'Pos_linea:'+ str(Pos_linea)

        if Resp.find("Denegado") == -1:                           # Entradas/Salidas Autorizadas
            Accion_Torniquete (Resp)

            Guardar_Autorizacion_Usuario_Tipos('T1', QR, Resp, '0')
            #Pos_linea = Buscar_Autorizados_ID_Tipo_1(QR)
            #Dato = Guardar_Autorizacion_General_Tipo_1(QR, Tiempo_Actual, Pos_linea, Resp, '1') # guardar un registro de lo autorizado
            Dato =''
            if      Resp == 'Access granted-E': Dato =  QR + '.' + Tiempo_Actual + '.1.0.0' + '\n'
            elif    Resp == 'Access granted-S': Dato =  QR + '.' + Tiempo_Actual + '.1.1.0' + '\n'

            #----desicion a quie envio lo autorizado
            Prioridad = Get_File(CONF_AUTORIZACION_QR).strip()
            if Prioridad == '0': # solo enviar lo autorizado al servidor
                Enviar_Autorizado_Server(Dato) # envio general
            if Prioridad == '1': # solo enviar lo autorizado al counter
                Enviar_Autorizado_Counter(Dato) # envio general

            return 1                                                # funcionamiento con normalidad
        else :                                                      # denegado
            Accion_Torniquete (Resp)
            return 1                                                # funcionamiento con normalidad
    #------------------------------------------------------------------------------------------------------------
    if  Validacion == 'T2': #falta enviar al counter

        Pos_linea, Resp = Decision_Tipo_2(QR, Tiempo_Actual)
        if PP_Mensajes:
            print 'Resp:'+ Resp
            print 'Pos_linea:'+ str(Pos_linea)

        if Resp.find("Denegado") == -1:                           # Entradas/Salidas Autorizadas
            Accion_Torniquete (Resp)
            Pos_linea = Buscar_Autorizados_ID_Tipo_2(QR)
            Dato = Guardar_Autorizacion_General_Tipo_2(QR, Tiempo_Actual, Pos_linea, Resp, '1') # guardar un registro de lo autorizado
            #----desicion a quie envio lo autorizado
            Prioridad = Get_File(CONF_AUTORIZACION_QR).strip()
            if Prioridad == '0': # solo enviar lo autorizado al servidor
                Enviar_Autorizado_Server(Dato) # envio general
            if Prioridad == '1': # solo enviar lo autorizado al counter
                Enviar_Autorizado_Counter(Dato) # envio general

            return 1                                                # funcionamiento con normalidad
        else :                                                      # denegado
            Accion_Torniquete (Resp)
            return 1                                                # funcionamiento con normalidad
    #------------------------------------------------------------------------------------------------------------
    if  Validacion == 'T2_1': #falta enviar al counter

        Pos_linea, Resp = Decision_Tipo_2_1(QR, Tiempo_Actual)
        if PP_Mensajes:
            print 'Resp:'+ Resp
            print 'Pos_linea:'+ str(Pos_linea)

        if Resp.find("Denegado") == -1:                           # Entradas/Salidas Autorizadas
            Accion_Torniquete (Resp)
            Pos_linea = Buscar_Autorizados_ID_Tipo_2_1(QR)
            Guardar_Autorizacion_Tipo_2_1(QR, Tiempo_Actual, Pos_linea, Resp, '1') # guardar un registro de lo autorizado
            #----desicion a quie envio lo autorizado
            Prioridad = Get_File(CONF_AUTORIZACION_QR).strip()
            if Prioridad == '0': # solo enviar lo autorizado al servidor
                Enviar_Autorizado_Server(Dato) # envio general
            if Prioridad == '1': # solo enviar lo autorizado al counter
                Enviar_Autorizado_Counter(Dato) # envio general
            return 1                                                # funcionamiento con normalidad
        else :                                                      # denegado
            Accion_Torniquete (Resp)
            return 1                                                # funcionamiento con normalidad
    #------------------------------------------------------------------------------------------------------------
    if  Validacion == 'T3': #falta enviar al counter

        Pos_linea, Resp,Incremento = Decision_Tipo_3(QR)
        if PP_Mensajes:
            print 'Resp:'+ Resp
            print 'Pos_linea:'+ str(Pos_linea)

        if Pos_linea != -1:
            #-------  ventana de tiempo 60 minutos
            Ventana = Ventana_tiempo_Tipo_3(QR,Tiempo_Actual)
            if Ventana == 1:

                Registro = QR + "." + Tiempo_Actual + ".1.0.1." + Incremento
                Accion_Torniquete (Resp)                                # Aciones del disposivo
                Guardar_Autorizacion_Tipo_3(Registro)                   # Guardado interno
                #----desicion a quie envio lo autorizado
                Prioridad = Get_File(CONF_AUTORIZACION_QR).strip()
                if Prioridad == '0': # solo enviar lo autorizado al servidor
                    Enviar_Autorizado_Server(Registro) # envio general
                if Prioridad == '1': # solo enviar lo autorizado al counter
                    Enviar_Autorizado_Counter(Registro) # envio general
                return 1                                                # funcionamiento con normalidad

            else:
                if PP_Mensajes: print 'Resp: '+'Denegado'
                Accion_Torniquete ('Denegado')
                return 1                                                # funcionamiento con normalidad
        else:
            if PP_Mensajes: print 'Resp: '+'Denegado'
            Accion_Torniquete ('Denegado')
            return 1                                                # funcionamiento con normalidad
    #------------------------------------------------------------------------------------------------------------
    else:   #No cumple parametros o nuevo formatos
        if PP_Mensajes: print 'No cumple parametros'
        Accion_Torniquete ("Denegado")
        return -2                                                # funcionamiento con normalidad
    #------------------------------------------------------------------------------------------------------------

    #NOTAS
    # return -1 # No cumple parametros
    # return 1  # funcionamiento con normalidad

























#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
#               Acciones en el Actuador (torniquete) y visualizadores
#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
def Accion_Torniquete (Res):
    global PP_Mensajes

    Res=Res.rstrip('\n')            # eliminar caracteres extras
    Res=Res.rstrip('\r')            # eliminar caracteres extras

    if Res == 'Access granted-E':
        #if PP_Mensajes: print "Access granted-E"
        Set_File(COM_LED , 'Access granted-E')
        Set_File(COM_RELE, 'Access granted-E')

        Set_File(COM_TX_RELE, 'Access granted-E')

    elif Res == 'Access granted-S':
        #if PP_Mensajes: print "Access granted-S"
        Set_File(COM_LED , 'Access granted-S')
        Set_File(COM_RELE, 'Access granted-S')

        Set_File(COM_TX_RELE, 'Access granted-E')

    else :
        #if PP_Mensajes: print "Denegado"
        Set_File(COM_LED, 'Error')

        Set_File(COM_TX_RELE, 'Error')



#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
#               Funciones principales para procesamiento de QR
#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
def Get_QR(Canal):
    if Canal == 0 :   Pal=    Get_File(COM_QR)
    if Canal == 1 :   Pal=    Get_File(COM_QR_S1)
    if Canal == 2 :   Pal=    Get_File(COM_QR_S2)
    Pal=Pal.rstrip('\n')
    Pal=Pal.rstrip('\r')
    return Pal
#---------------------------------------------------------
def revicion_QR ():
    if Get_File(STATUS_QR) == '1':
        Decision_General(0)
        Clear_File(STATUS_QR)
    elif Get_File(STATUS_QR_S1) == '1':
        Decision_General(1)
        Clear_File(STATUS_QR_S1)
    elif Get_File(STATUS_QR_S2) == '1':
        Decision_General(2)
        Clear_File(STATUS_QR_S2)

#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
print 'Ciclo principal lectura QR'
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
    revicion_QR ()
