# -*- coding: utf-8 -*-
# ---------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Libreria personal para procesar un qr.




# ideas a implementar





"""
# ---------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------
# Librerias creadas para multi procesos o hilos -------------
import datetime
import time
import commands
import sys
import socket
import os

# ---------------------------------
#           Librerias personales
# ---------------------------------

from lib.Lib_File import *  # importar con los mismos nombres
from lib.Lib_Rout import *  # importar con los mismos nombres
from lib.Verificar_Usuarios import *  # importar con los mismos nombres

# -------------------------------------------------------
# inicio de variable	--------------------------------------
PP_Mensajes = 0     # 0: NO print  1: Print

# Leer_Estado(13)  #print Direc_Torniquete
Direc_Torniquete = Get_File(CONF_DIREC_RELE)
Estados = '6'  # estados del dispositivos para visualizar en los leds
Estados_Antes = '0'
T_estado = 0

Hay_Internet = 1


# ---------------------------------------------------------
#                       Tipo_1
# ---------------------------------------------------------
def Guardar_Autorizacion_Tipo_1(QR, Tiempo_Actual, Pos_linea, Res, Status_Internet):
    global PP_Mensajes

    Rest = '0'  # convercion de respuesta  # 0: entrada.1: salida .
    Tipo = '1'  # 1: QR
    if Res == 'Access granted-E':
        Rest = '0'  # respuesta
        Dato = QR + '.' + Tiempo_Actual + '.' + Tipo + \
            '.' + Rest + '.' + Status_Internet + '\n'
        if PP_Mensajes:
            print 'Reguistro: ' + Dato
            # print Pos_linea
        # --------   reguistor  para el counter
        # Set_File(CONT_DATA,Co+Ti+'.'+Qr_Te+'.0.'+I_N_S+'\n')
        # Set_File(CONT_FlAG,'1')
        # --------   Reguistro en el dispositivo

        if Pos_linea != -1:
            Update_Line(TAB_AUTO_TIPO_1, Pos_linea, Dato)
        else:
            Add_Line_End(TAB_AUTO_TIPO_1, Dato)
        # --------   Reguistro generel de autorizaciones
        # desavilitado

    elif Res == 'Access granted-S':
        Rest = '1'  # respuesta

        Dato = QR + '.' + Tiempo_Actual + '.' + Tipo + \
            '.' + Rest + '.' + Status_Internet + '\n'
        if PP_Mensajes:
            print 'Reguistro: ' + Dato
            # print Pos_linea
        # --------   reguistor  para el counter
        # Set_File(CONT_DATA,Co+Ti+'.'+Qr_Te+'.0.'+I_N_S+'\n')
        # Set_File(CONT_FlAG,'1')
        # --------   Reguistro en el dispositivo

        if Pos_linea != -1:
            Update_Line(TAB_AUTO_TIPO_1, Pos_linea, Dato)
        else:
            Add_Line_End(TAB_AUTO_TIPO_1, Dato)
        # --------   Reguistro generel de autorizaciones
        # desavilitado

# envio autorizados a Counter


def Enviar_Tipo1_Counter_Autorizado(Dato):
    Enviar_Tipo3_Counter_Autorizado(Dato)


def Eleccion_Tipo_1(QR, Tiempo_Actual, Quien_Autoriza):

    if Quien_Autoriza == 'Counter':
        if Get_File(CONT_SEND_FLAG_PATH) == "":
            Heder = 'header.authTicket.1.'+Tiempo_Actual+'\n'
            Dato_TX = QR + '\n'
            Total_TX = Heder + Dato_TX
            # print Total_TX
            Set_File(CONT_SEND_DATA_PATH, Total_TX)  # enviar el QR
            Set_File(CONT_SEND_FLAG_PATH, '1')
            T_E = T_Antes = -1
            while 1:
                if Get_File(CONT_RECEIVED_FLAG_PATH) == "1":
                    print 'Respuesta :'
                    Resp = Get_File(CONT_RECEIVED_DATA_PATH)
                    Resps = Resp.split("\n")

                    # print Resps[0]
                    # print Resps[1]
                    if len(Resps) > 1:
                        Heder_res = Resps[0].split('.')
                        Accion_res = Resps[1].split('.')
                        # print Heder_res[1]
                        # print Accion_res[0]

                        if Heder_res[1] == 'authTicket':
                            Accion_Torniquete(Accion_res[0])   # accion fisica
                            print 'Tipo: ' + Accion_res[0]
                            if "Access granted" in Accion_res[0]:
                                #Dato_Rele = "¿00000004000" + str(CONF_TIEM_RELE) + "?"
                                #Set_File(COM_TX_RELE, Dato_Rele)


                                Guardar_Autorizacion_Tipo_1(
                                    QR, str(Tiempo_Actual), -1, Accion_res[0], str(1))
                            Clear_File(CONT_RECEIVED_DATA_PATH)
                            Clear_File(CONT_RECEIVED_FLAG_PATH)
                            break
                        else:
                            print 'Es otra comunicacion'
                            #Accion_Torniquete ('Denegado')

                if T_Antes == -1:
                    T_E = int(time.time()*1000.0)  # Tiempo
                    T_Antes = T_E
                else:
                    T_E = int(time.time()*1000.0)  # Tiempo
                Tiempo_diferencia = T_E - T_Antes
                # print str(Tiempo_diferencia)
                if Tiempo_diferencia >= 2000:
                    print 'procesar por no respuesta T:' + str(Tiempo_diferencia)
                    Clear_File(CONT_SEND_DATA_PATH)
                    #Clear_File(CONT_SEND_FLAG_PATH)
                    Set_File(CONT_SEND_FLAG_PATH,'3')
                    Clear_File(CONT_RECEIVED_DATA_PATH)
                    Clear_File(CONT_RECEIVED_FLAG_PATH)
                    Decision_Dispositivo(QR, Tiempo_Actual)
                    #Accion_Torniquete ('Denegado')

                    break
        else:
            print 'Error en la comunicacion : Flag No vacio'
            #Accion_Torniquete('Denegado')
            Decision_Dispositivo(QR, Tiempo_Actual)

# ---------------------------------------------------------


def Guardar_Autorizacion_Tipo_2(QR, Tiempo_Actual, Pos_linea, Res, Status_Internet):
    global PP_Mensajes

    Rest = '0'  # convercion de respuesta  # 0: entrada.1: salida .
    Tipo = '1'  # 1: QR
    if Res == 'Access granted-E':
        Rest = '0'  # respuesta
        Dato = QR + '.' + Tiempo_Actual + '.' + Tipo + \
            '.' + Rest + '.' + Status_Internet + '\n'
        if PP_Mensajes:
            print 'Reguistro: ' + Dato
            # print Pos_linea
        # --------   reguistor  para el counter
        # Set_File(CONT_DATA,Co+Ti+'.'+Qr_Te+'.0.'+I_N_S+'\n')
        # Set_File(CONT_FlAG,'1')
        # --------   Reguistro en el dispositivo

        if Pos_linea != -1:
            Update_Line(TAB_AUTO_TIPO_2, Pos_linea, Dato)
        else:
            Add_Line_End(TAB_AUTO_TIPO_2, Dato)
        # --------   Reguistro generel de autorizaciones
        # desavilitado

    elif Res == 'Access granted-S':
        Rest = '1'  # respuesta

        Dato = QR + '.' + Tiempo_Actual + '.' + Tipo + \
            '.' + Rest + '.' + Status_Internet + '\n'
        if PP_Mensajes:
            print 'Reguistro: ' + Dato
            # print Pos_linea
        # --------   reguistor  para el counter
        # Set_File(CONT_DATA,Co+Ti+'.'+Qr_Te+'.0.'+I_N_S+'\n')
        # Set_File(CONT_FlAG,'1')
        # --------   Reguistro en el dispositivo

        if Pos_linea != -1:
            Update_Line(TAB_AUTO_TIPO_2, Pos_linea, Dato)
        else:
            Add_Line_End(TAB_AUTO_TIPO_2, Dato)
        # --------   Reguistro generel de autorizaciones
        # desavilitado

# ---------------------------------------------------------


def Guardar_Autorizacion_Tipo_2_1(QR, Tiempo_Actual, Pos_linea, Res, Status_Internet):
    global PP_Mensajes

    Rest = '0'  # convercion de respuesta  # 0: entrada.1: salida .
    Tipo = '1'  # 1: QR
    if Res == 'Access granted-E':
        Rest = '0'  # respuesta
        Dato = QR + '.' + Tiempo_Actual + '.' + Tipo + \
            '.' + Rest + '.' + Status_Internet + '\n'
        if PP_Mensajes:
            print 'Reguistro: ' + Dato
            # print Pos_linea
        # --------   reguistor  para el counter
        # Set_File(CONT_DATA,Co+Ti+'.'+Qr_Te+'.0.'+I_N_S+'\n')
        # Set_File(CONT_FlAG,'1')
        # --------   Reguistro en el dispositivo

        if Pos_linea != -1:
            Update_Line(TAB_AUTO_TIPO_2_1, Pos_linea, Dato)
        else:
            Add_Line_End(TAB_AUTO_TIPO_2_1, Dato)
        # --------   Reguistro generel de autorizaciones
        # desavilitado

    elif Res == 'Access granted-S':
        Rest = '1'  # respuesta

        Dato = QR + '.' + Tiempo_Actual + '.' + Tipo + \
            '.' + Rest + '.' + Status_Internet + '\n'
        if PP_Mensajes:
            print 'Reguistro: ' + Dato
            # print Pos_linea
        # --------   reguistor  para el counter
        # Set_File(CONT_DATA,Co+Ti+'.'+Qr_Te+'.0.'+I_N_S+'\n')
        # Set_File(CONT_FlAG,'1')
        # --------   Reguistro en el dispositivo

        if Pos_linea != -1:
            Update_Line(TAB_AUTO_TIPO_2_1, Pos_linea, Dato)
        else:
            Add_Line_End(TAB_AUTO_TIPO_2_1, Dato)
        # --------   Reguistro generel de autorizaciones
        # desavilitado


# ---------------------------------------------------------
#                       Tipo_3
# ---------------------------------------------------------
def Ventana_tiempo_Tipo_3(QR, Tiempo_Actual):

    Tiempo_Max = 3600*24  # quemado 60 minutos   3600 segundos *24
    Vector = QR.split(".")
    T_inicio = int(Vector[4])

    if Tiempo_Actual > T_inicio:
        Resta = (int(Tiempo_Actual) - int(Vector[4]))/1000
        # print Resta
        if Resta >= Tiempo_Max:
            return -1
        else:
            return 1


def Eleccion_Tipo_3(QR, Tiempo_Actual, Quien_Autoriza):

    if Quien_Autoriza == 'Counter':
        if Ventana_tiempo_Tipo_3(QR, Tiempo_Actual) == 1:
            if Get_File(CONT_SEND_FLAG_PATH) == "":
                Heder = 'header.authTicket.1.'+Tiempo_Actual+'\n'
                Dato_TX = QR + '\n'
                Total_TX = Heder + Dato_TX
                # print Total_TX
                Set_File(CONT_SEND_DATA_PATH, Total_TX)  # enviar el QR
                Set_File(CONT_SEND_FLAG_PATH, '1')
                T_E = T_Antes = -1
                while 1:
                    if Get_File(CONT_RECEIVED_FLAG_PATH) == "1":
                        print 'Respuesta :'
                        Resp = Get_File(CONT_RECEIVED_DATA_PATH)
                        Resps = Resp.split("\n")

                        # print Resps[0]
                        # print Resps[1]
                        if len(Resps) > 1:
                            Heder_res = Resps[0].split('.')
                            Accion_res = Resps[1].split('.')
                            # print Heder_res[1]
                            # print Accion_res[0]

                            if Heder_res[1] == 'authTicket':
                                # accion fisica
                                Accion_Torniquete(Accion_res[0])
                                print 'Tipo: ' + Accion_res[0]
                                print 'Contador:' + Accion_res[1]
                                # Guardado_Tipo_3()                      # cambiar y mejorar para las nuevas convenciones
                                if "Access granted" in Accion_res[0]:
                                    # print QR
                                    Guardar_Autorizacion_Tipo_3(
                                        QR + "." + Tiempo_Actual + ".1.0.1." + Accion_res[1])
                                Clear_File(CONT_RECEIVED_DATA_PATH)
                                Clear_File(CONT_RECEIVED_FLAG_PATH)
                                break
                            else:
                                print 'Es otra comunicacion'
                                #Accion_Torniquete ('Denegado')

                    if T_Antes == -1:
                        T_E = int(time.time()*1000.0)  # Tiempo
                        T_Antes = T_E
                    else:
                        T_E = int(time.time()*1000.0)  # Tiempo
                    Tiempo_diferencia = T_E - T_Antes
                    # print str(Tiempo_diferencia)
                    if Tiempo_diferencia >= 2000:
                        print 'procesar por no respuesta T:' + str(Tiempo_diferencia)
                        Clear_File(CONT_SEND_DATA_PATH)
                        Clear_File(CONT_SEND_FLAG_PATH)
                        Clear_File(CONT_RECEIVED_DATA_PATH)
                        Clear_File(CONT_RECEIVED_FLAG_PATH)
                        Decision_Dispositivo(QR, Tiempo_Actual)
                        #Accion_Torniquete ('Denegado')

                        break
            else:
                print 'Error en la comunicacion : Flag No vacio'
                Accion_Torniquete('Denegado')
        else:
            print 'Tiempo vencido:'
            Accion_Torniquete('Denegado')

# ------------------------------------------------------------------------


def Guardar_Autorizacion_Tipo_3(usuario):

    puntos = usuario.count(".")
    if puntos == 9:
        Add_File(TAB_AUTO_TIPO_3, usuario+'\n')
        s = usuario.split(".")
        ID_1 = s[1] + '.' + s[2] + '.' + s[3]
        Usuarios = Get_File(TAB_USER_TIPO_3)
        newUsuarios = ""
        isFirst = True
        for linea in Usuarios.split('\n'):
            if linea.count('.') >= 1:
                ticket = linea.rstrip('\n')
                ticket = ticket.rstrip('\r')
                s2 = ticket.split(".")
                ID = s2[0] + '.' + s2[1] + '.' + s2[2]
                if ID_1 == ID and isFirst:
                    if(int(s[-1]) < int(s[3])):
                        newUsuarios += s[1] + '.' + s[2] + \
                            '.' + s[3] + '.' + s[-1] + "\n"
                    isFirst = False
                else:
                    newUsuarios += linea + "\n"
        Clear_File(TAB_USER_TIPO_3)
        Add_File(TAB_USER_TIPO_3, newUsuarios)

    else:
        print 'No cumple parametros'

# ------------------------------------------------------------------------


def Guardado_Tipo_3(QR, Tiempo_Actual, Pos_linea, Res, Status_Internet):

    global PP_Mensajes

    Rest = '0'  # convercion de respuesta  # 0: entrada.1: salida .
    Tipo = '1'  # 1: QR
    if Res == 'Access granted-E':
        Rest = '0'  # respuesta
        Dato = QR + '.' + Tiempo_Actual + '.' + Tipo + \
            '.' + Rest + '.' + Status_Internet + '\n'
        if PP_Mensajes:
            print 'Reguistro: ' + Dato
            # print Pos_linea
        # --------   reguistor  para el counter
        Set_File(CONT_AUTORIZADOS, Dato+'\n')
        Set_File(CONT_FlAG_AUTORIZADOS, '1')
        # --------   Reguistro en el dispositivo

        if Pos_linea != -1:
            Update_Line(TAB_AUTO_TIPO_3, Pos_linea, Dato)
        else:
            Add_Line_End(TAB_AUTO_TIPO_3, Dato)
        # --------   Reguistro generel de autorizaciones
        # desavilitado

    elif Res == 'Access granted-S':
        Rest = '1'  # respuesta

        Dato = QR + '.' + Tiempo_Actual + '.' + Tipo + \
            '.' + Rest + '.' + Status_Internet + '\n'
        if PP_Mensajes:
            print 'Reguistro: ' + Dato
            # print Pos_linea
        # --------   reguistor  para el counter
        Set_File(CONT_AUTORIZADOS, Dato+'\n')
        Set_File(CONT_FlAG_AUTORIZADOS, '1')
        # --------   Reguistro en el dispositivo

        if Pos_linea != -1:
            Update_Line(TAB_AUTO_TIPO_3, Pos_linea, Dato)
        else:
            Add_Line_End(TAB_AUTO_TIPO_3, Dato)
        # --------   Reguistro generel de autorizaciones
        # desavilitado
# --------------------------------------------------
# envio autorizados a Counter


def Enviar_Tipo3_Counter_Autorizado(Dato):
    # print 'enviando dato'
    heder = 'header.delTickets'
    flag_Send = Get_File(CONT_SEND_FLAG_PATH)
    if flag_Send == '':
        # print 'basio'
        Set_File(CONT_SEND_DATA_PATH, heder+'.1\n' + Dato+'\n')
        Set_File(CONT_SEND_FLAG_PATH, '1')

    else:
        # print '1,2 o 3'
        Data = Get_File(CONT_SEND_DATA_PATH)
        # print Data
        if Data == '':
            # print 'esta basio'
            Set_File(CONT_SEND_DATA_PATH, heder+'.1\n' + Dato+'\n')
            # Set_File(CONT_SEND_FLAG_PATH,'1')
        else:
            Split_Data = Data.split("\n")
            Header = Split_Data[0].split(".")
            Contador = int(Header[2])+1
            # print Contador
            Datos = Split_Data[1:(int(Header[2])+1)]
            Data = ''
            for linea in Datos:
                # print linea
                Data += linea + '\n'

            Total = heder + '.' + str(Contador) + '\n' + Data + Dato + '\n'
            # print Total
            Set_File(CONT_SEND_DATA_PATH, heder + '.' +
                     str(Contador) + '\n' + Data + Dato + '\n')


# ---------------------------------------------------------
def Respuesta_Con_Internet(QR_RUT, T_A,  IDT, Respuesta, QR):

    if QR_RUT == 'QR':
        #Respuesta = Respuesta.text
        if PP_Mensajes:
            print "Respuesta QR, con internet:" + Respuesta
        Set_File(COM_LED, '1')  # Cambio_Estado_Led('1')
        Decision_Torniquete(Respuesta, QR, "", T_A, '1', '0')


# -------------------------------------------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------------------------------------------
#                   Deisiones para autorizar el Qr
# -------------------------------------------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------------------------------------------

def Decision():
    global PP_Mensajes

    QR_RUT = 'QR'
    T_A = str(int(time.time()*1000.0))  # Tiempo()

    if PP_Mensajes:
        print 'Nuevo------------------------------------'
        print 'Tiempo: ', "%s" % T_A

    # Prepararacion de informacion para tratamiento
    Set_File(COM_BUZZER, '1')  # sonido eliminar si no es necesario
    R_Q = Get_QR()

    if PP_Mensajes:
        print 'QR: ' + R_Q

    #if R_Q == 'Igual':
    #    R_Q = Get_File(COM_QR)

    # Decision dependiendo del estado del dispsotivo y configuracion de prioridades
    # Hay_Internet =1 # /////////////////////////// hojo comentar

    flag_Send = Get_File(CONT_SEND_FLAG_PATH)
    # print flag_Send
    if flag_Send == '':
        if PP_Mensajes:
            print ' --Decision Counter--'
        Decision_Counter(R_Q, T_A)
    else:
        if PP_Mensajes:
            print ' --Decision Dispositivo--'
        Decision_Dispositivo(R_Q, T_A)

# ---------------------------------------------------------
# ----       Ruta para que autorise el servidor
# ---------------------------------------------------------


def Decision_Server(QR, Tiempo_Actual):
    print 'Autorisa el servidor'

# ---------------------------------------------------------
# ----       Ruta para que autorise el counter
# ---------------------------------------------------------


def Decision_Counter(QR, Tiempo_Actual):
    puntos = QR.count(".")
    if PP_Mensajes:
        print 'Puntas_separacion Decision_Counter: ' + str(puntos)

    # -----------------------------------------------------------------------------------------
    #           Formato 3 :         09. azAZ09. azAZ09. azAZ09. 09  -> tipo.id.id.id.tiempo init.   tiken un solo uso
    # -----------------------------------------------------------------------------------------
    if puntos == 1:
        Eleccion_Tipo_1(QR, Tiempo_Actual, 'Counter')
        if PP_Mensajes:
            print '-----Formato 1: azAZ09. azAZ09'
            print 'Autoriza el counter'

    elif puntos == 4:
        Eleccion_Tipo_3(QR, Tiempo_Actual, 'Counter')
        if PP_Mensajes:
            print '-----Formato 3: 09. azAZ09. azAZ09. azAZ09. 09'
            print 'Autoriza el counter'

    else:
        print 'Otro tipo de QR'
        Accion_Torniquete('Denegado')

# ---------------------------------------------------------
# ----       Ruta para que autorise el maestro Dispositivo
# ---------------------------------------------------------


def Decision_Maestro_dispositivo(QR, Tiempo_Actual):
    print 'Autorisa el Maestro disposivo'

# ---------------------------------------------------------
# ----       Ruta para que autorise el Dispositivo
# ---------------------------------------------------------


def Decision_Dispositivo(QR, Tiempo_Actual):

    puntos = QR.count(".")
    # if PP_Mensajes: print 'Puntas_separacion: ' + str(puntos)

    # -----------------------------------------------------------------------------------------
    #           Formato 1 :         azAZ09. azAZ09                  -> sha256.id  si exite el ID entra
    # -----------------------------------------------------------------------------------------
    if puntos == 1:
        if PP_Mensajes:
            print '-----Formato 1: azAZ09. azAZ09 '

        Pos_linea, Resp = Decision_Tipo_1(QR)

        if PP_Mensajes:
            print 'Resp:' + Resp
            print 'Pos_linea:' + str(Pos_linea)

        Accion_Torniquete(Resp)
        # guardar un registro de lo autorizado
        Guardar_Autorizacion_Tipo_1(QR, Tiempo_Actual, Pos_linea, Resp, '1')
        if Resp == 'Access granted-E':
            Registro = QR + "." + Tiempo_Actual + ".1.0.1"
            Enviar_Tipo1_Counter_Autorizado(Registro)
        elif Resp == 'Access granted-S':
            Registro = QR + "." + Tiempo_Actual + ".1.1.1"
            Enviar_Tipo1_Counter_Autorizado(Registro)
    # -----------------------------------------------------------------------------------------
    #           Formato 2 :         azAZ09. azAZ09. 09              -> sha256.id.tiempo ventana quemado 60 minutos
    # -----------------------------------------------------------------------------------------
    elif puntos == 2:
        if PP_Mensajes:
            print '-----Formato 2: azAZ09. azAZ09. 09 '

        Pos_linea, Resp = Decision_Tipo_2(QR)

        # -------  ventana de tiempo 60 minutos
        Ventana = Ventana_tiempo_Tipo_2(QR, Tiempo_Actual, Resp)
        if Ventana == 1:
            if PP_Mensajes:
                print 'Dentro del rango o Salida'
                print 'Resp:' + Resp
                print 'Pos_linea:' + str(Pos_linea)
            Accion_Torniquete(Resp)
            # guardar un registro de lo autorizado
            Guardar_Autorizacion_Tipo_2(
                QR, Tiempo_Actual, Pos_linea, Resp, '1')
        else:
            if PP_Mensajes:
                print 'Denegado'
            Accion_Torniquete('Denegado')

    # -----------------------------------------------------------------------------------------
    #           Formato 2.1 :       azAZ09. azAZ09. 09. 09          -> sha256.id.tiempo init.tiempo fin.
    # -----------------------------------------------------------------------------------------
    elif puntos == 3:
        if PP_Mensajes:
            print '-----Formato 2_1: azAZ09. azAZ09. 09. 09'

        Pos_linea, Resp = Decision_Tipo_2_1(QR)

        # -------  ventana de tiempo 60 minutos
        Ventana = Ventana_tiempo_Tipo_2_1(QR, Tiempo_Actual, Resp)
        if Ventana == 1:
            if PP_Mensajes:
                print 'Dentro del rango o Salida'
                print 'Resp:' + Resp
                print 'Pos_linea:' + str(Pos_linea)
            Accion_Torniquete(Resp)
            # guardar un registro de lo autorizado
            Guardar_Autorizacion_Tipo_2_1(QR, Tiempo_Actual, Pos_linea, Resp, '1')
        else:
            if PP_Mensajes:
                print 'Denegado'
            Accion_Torniquete('Denegado')

    # -----------------------------------------------------------------------------------------
    #           Formato 3 :         09. azAZ09. azAZ09. azAZ09. 09  -> tipo.id.id.id.tiempo init.   tiken un solo uso
    # -----------------------------------------------------------------------------------------
    elif puntos == 4:
        if PP_Mensajes:
            print '-----Formato 3: 09. azAZ09. azAZ09. azAZ09. 09'

        Pos_linea, Resp, Incremento = Decision_Tipo_3(QR)
        # print Pos_linea
        # print Resp
        # print Incremento
        if Pos_linea != -1:
            # -------  ventana de tiempo 60 minutos
            Ventana = Ventana_tiempo_Tipo_3(QR, Tiempo_Actual)
            if Ventana == 1:

                Registro = QR + "." + Tiempo_Actual + ".1.0.1." + Incremento

                if PP_Mensajes:
                    print 'Resp: ' + Resp
                    # print 'Registro: '+ Registro

                Accion_Torniquete(Resp)
                Guardar_Autorizacion_Tipo_3(Registro)       # Guardado interno
                Enviar_Tipo3_Counter_Autorizado(Registro)   # enviar a la comunicaiones

            else:
                if PP_Mensajes:
                    print 'Resp: '+'Denegado'
                Accion_Torniquete('Denegado')
        else:
            if PP_Mensajes:
                print 'Resp: '+'Denegado'
            Accion_Torniquete('Denegado')

    else:
        if PP_Mensajes:
            print 'Formato NO valido: '+'Denegado'
        Accion_Torniquete('Denegado')


# -------------------------------------------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------------------------------------------
#               Acciones en el Actuador (torniquete) y visualizadores
# -------------------------------------------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------------------------------------------
def Accion_Torniquete(Res):
    global PP_Mensajes

    Res = Res.rstrip('\n')            # eliminar caracteres extras
    Res = Res.rstrip('\r')            # eliminar caracteres extras

    if Res == 'Access granted-E':
        # if PP_Mensajes: print "Access granted-E"
        Dato_Rele = "¿00000004000" + str(Get_File(CONF_TIEM_RELE)) + "?"
        Set_File(COM_TX_RELE,Dato_Rele)
        Set_File(COM_LED, 'Access granted-E')
        Set_File(COM_RELE, 'Access granted-E')

    elif Res == 'Access granted-S':
        # if PP_Mensajes: print "Access granted-S"
        Dato_Rele = "¿00000004000" + str(Get_File(CONF_TIEM_RELE)) + "?"
        Set_File(COM_TX_RELE,Dato_Rele)
        Set_File(COM_LED, 'Access granted-S')
        Set_File(COM_RELE, 'Access granted-S')
    else:
        # if PP_Mensajes: print "Denegado"
        Set_File(COM_LED, 'Error')


# -------------------------------------------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------------------------------------------
#               Funciones principales para procesamiento de QR
# -------------------------------------------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------------------------------------------
def Get_QR():
    Pal = Get_File(COM_QR)
    Pal = Pal.rstrip('\n')
    Pal = Pal.rstrip('\r')
    Pal = Pal.replace("<", "")
    Pal = Pal.replace(">", "")
    return Pal
# ---------------------------------------------------------


def revicion_QR():
    if Get_File(STATUS_QR) == '1':
        Decision()
        Clear_File(STATUS_QR)


# -------------------------------------------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------------------------------------------
print 'Ciclo principal lectura QR'
Set_File(COM_LED, '0')
# -------------------------------------------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------------------------------------------

while 1:
    # ---------------------------------------------------------
    #  Proceso 0: Tiempo de espera para disminuir proceso
    # ---------------------------------------------------------
    time.sleep(0.05)
    # ---------------------------------------------------------
    # Proceso 4: Procesamiento del QR
    # ---------------------------------------------------------
    revicion_QR()
