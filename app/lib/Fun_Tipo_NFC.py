#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Libreria personal para procesar un qr.




# ideas a implementar





"""
#---------------------------------------------------------------------------------------

#---------------------------------------------------------------------------------------
#                                   importar complementos
#---------------------------------------------------------------------------------------
import datetime
import time

from lib.Lib_File import *            # importar con los mismos nombres
from lib.Lib_Rout import *            # importar con los mismos nombres
from lib.Lib_Encryp import *            # importar con los mismos nombres


#-------------------------------------------------------
# inicio de variable	--------------------------------------

FTN_Mensajes = 0     # 0: NO print  1: Print



#---------------------------------------------------------
#---------------------------------------------------------
#----                   ID _ NFC
#---------------------------------------------------------
#---------------------------------------------------------

def Decision_Tipo_NFC(NFC_Md5):
    global FTN_Mensajes


    Veri_Impreso,Usuario = Buscar_NFC(NFC_Md5)
    #print Veri_Impreso

    if Veri_Impreso != 0 :
        Pos_linea,Tipo_IO =Buscar_acceso_NFC(NFC_Md5)
        if FTN_Mensajes:
            print 'Exite'
            print Pos_linea
            print Tipo_IO
        if Pos_linea == -1 :    return -1,'Access granted-E', Usuario    # esta el usuario pero no tiene registro
        else:
            if Tipo_IO == '0':      # 0: entrada.1: salida .
                return Pos_linea,'Access granted-S', Usuario             # registro de entrada otorga salida
            elif Tipo_IO == '1':    # 0: entrada.1: salida .
                return Pos_linea,'Access granted-E', Usuario             # registro de entrada otorga Entrada

        #return -1,'Access granted-E', Usuario
    else:
        return -1,'Denegado',''

    return -1,'Denegado',''

#---------------------------------------------------------
def Buscar_NFC(NFC): #mejorar por que podia pasa cualquiera

    Contador=0
    Usuarios = Get_File(TAB_USER_TIPO_6)
    for linea in Usuarios.split('\n'):
        #print linea.count('.')
        if linea.count('.') >= 1:
            Vector = linea.split(".")
            TaCadena = len (NFC)
            if 	NFC == Vector[1]:
                Contador +=1
                #print Vector[1]
                return Contador,linea

    return Contador,""

#---------------------------------------------------------
def Buscar_acceso_NFC(ID_1):
    Usuarios = Get_File(TAB_AUTO_TIPO_6)
    Pos_linea=1  # comiensa en 1 para convenzar la linea cero
    for linea in Usuarios.split('\n'):
        if linea.count('.') >=1:
            #print linea
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")
            if 	ID_1 ==	s2[2]:      return Pos_linea, s2[6] # retorno el estado y linea del usuarios
        Pos_linea= 1 + Pos_linea
    return -1,-1

#---------------------------------------------------------
def Guardar_Autorizacion_General_NFC(NFC, Tiempo_Actual, Pos_linea, Res, Status_Internet):
    global FTN_Mensajes

    Rest = '0' #    convercion de respuesta  # 0: entrada.1: salida .
    Tipo = '11' #    11: Generico NFC

    if      Res == 'Access granted-E':

        Rest = '0' #respuesta
        Dato = '6.' + NFC + '.' + Tiempo_Actual +  '.' + Tipo +  '.' + Rest +  '.' + Status_Internet + '\n'

        if FTN_Mensajes:
            print Tipo+'hh'
            print 'Registro: ' + Dato

        if Pos_linea != -1 :    Update_Line(TAB_AUTO_TIPO_6, Pos_linea, Dato)
        else:                   Add_Line_End(TAB_AUTO_TIPO_6, Dato)

        #--------   Registro generel de autorizaciones para aforo?
        # desavilitado

        return Dato


    elif    Res == 'Access granted-S':

        Rest = '1' #respuesta
        Dato = '6.' + NFC + '.' + Tiempo_Actual +  '.' + Tipo +  '.' + Rest +  '.' + Status_Internet + '\n'
        if FTN_Mensajes:
            print 'Reguistro: ' + Dato

        if Pos_linea != -1 :    Update_Line(TAB_AUTO_TIPO_6, Pos_linea, Dato)
        else:                   Add_Line_End(TAB_AUTO_TIPO_6, Dato)
        #--------   Registro generel de autorizaciones para aforo?
        # desavilitado

        return Dato
#---------------------------------------------------------








#---------------------------------------------------------
def Enviar_Autorizado_Counter(Dato):
    Prioridad = Get_File(CONF_AUTORIZACION_QR)
    if Prioridad == '1' or Prioridad == '3':   #revizar tabla de Permisos
        heder = 'header.delTickets'
        flag_Send = Get_File(CONT_SEND_FLAG_PATH)
        if flag_Send == '':
            #print 'basio'
            Set_File(CONT_SEND_DATA_PATH, heder+'.1\n' + Dato+'\n')
            Set_File(CONT_SEND_FLAG_PATH,'1')
        else:
            #print '1,2 o 3'
            Data = Get_File(CONT_SEND_DATA_PATH)
            #print Data
            if Data == '':
                #print 'esta basio'
                Set_File(CONT_SEND_DATA_PATH, heder+'.1\n' + Dato+'\n')
                #Set_File(CONT_SEND_FLAG_PATH,'1')
            else:
                Split_Data = Data.split("\n")
                Header = Split_Data[0].split(".")
                Contador = int(Header[2])+1
                #print Contador
                Datos = Split_Data[1:(int(Header[2])+1)]
                Data=''
                for linea in Datos:
                    #print linea
                    Data += linea + '\n'
                Total = heder + '.' + str(Contador) + '\n' + Data + Dato + '\n'
                #print Total
                Set_File(CONT_SEND_DATA_PATH, heder + '.' + str(Contador) + '\n' + Data + Dato + '\n')



#---------------------------------------------------------
#---------------------------------------------------------
#-------            Envios genelares de informacion a counter o servidor
#---------------------------------------------------------
#---------------------------------------------------------

def Enviar_NFC_Counter(QR, Tiempo_Actual):
    global FTN_Mensajes
    Flag_Revision_Time=int(time.time()*1000.0)
    Await_time=0.001
    while 1:
        time.sleep(Await_time)
        if Get_File(CONT_SEND_FLAG_PATH) == "":
            Heder = 'header.authTicket.1.'+Tiempo_Actual+'\n'
            Dato_TX = QR + '\n'
            Total_TX = Heder + Dato_TX
            # print Total_TX
            Set_File(CONT_SEND_DATA_PATH, Total_TX)  # enviar el QR
            Set_File(CONT_SEND_FLAG_PATH, '1')
            T_E = T_Antes = -1
            while 1:
                time.sleep(Await_time)
                if Get_File(CONT_RECEIVED_FLAG_PATH) == "1":
                    if FTN_Mensajes:    print 'Respuesta :'
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
                            if FTN_Mensajes:
                                print 'Tipo: ' + Accion_res[0]
                                print 'Contador:' + Accion_res[1]

                            Clear_File(CONT_RECEIVED_DATA_PATH)
                            Clear_File(CONT_RECEIVED_FLAG_PATH)
                            return Accion_res[0], Accion_res[1]

                        else:
                            if FTN_Mensajes:
                                print 'Es otra comunicacion'

                if T_Antes == -1:
                    T_E = int(time.time()*1000.0)  # Tiempo
                    T_Antes = T_E
                else:
                    T_E = int(time.time()*1000.0)  # Tiempo
                Tiempo_diferencia = T_E - T_Antes
                # print str(Tiempo_diferencia)
                if Tiempo_diferencia >= 2000:
                    if FTN_Mensajes:    print 'procesar por no respuesta T:' + str(Tiempo_diferencia)
                    Clear_File(CONT_SEND_DATA_PATH)
                    Clear_File(CONT_SEND_FLAG_PATH)
                    Clear_File(CONT_RECEIVED_DATA_PATH)
                    Clear_File(CONT_RECEIVED_FLAG_PATH)
                    return 'Error',"-1"
        if int(time.time()*1000.0)-Flag_Revision_Time > 1000:
            break
    if FTN_Mensajes:    print 'Error en la comunicacion : Flag No vacio'
    return 'Error',"-1"

#---------------------------------------------------------

def Enviar_Autorizado_Server(Dato):
    #--------   Registro generel para envio al servidor
    Add_Line_End(TAB_ENV_SERVER, Dato)  # para envio al servidor
