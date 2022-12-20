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
from lib.Lib_Regular_Expression import *   #


#-------------------------------------------------------
# inicio de variable	--------------------------------------

FTQ_Mensajes = 0     # 0: NO print  1: Print



#---------------------------------------------------------
#----       Validar el tipo de QR
#---------------------------------------------------------
def Validar_QR(QR):
    global FTQ_Mensajes
    TaCadena = len (QR)
    Inicio = QR[0:1]
    Fin = QR[TaCadena-1:TaCadena]
    if TaCadena >= 3:
        if (Inicio == '<' ) and (Fin == '>'):
            QR = QR.replace ("<","")
            QR = QR.replace (">","")
            #print QR
            Validacion = Validar_QR_Fusepong(QR)
            if  Validacion != '':
                if FTQ_Mensajes:    print Validacion +' : '+ QR
                return Validacion, QR
            else:                                   return '', QR   # No cumple parametros
        else:                                       return '', QR   # No cumple parametros
    else:                                           return '', QR   # No cumple parametros

#---------------------------------------------------------
#---------------------------------------------------------
#----                   TIPO 1_1 QR con identificador impreso
#---- Formato 1 :         -azAZ09. azAZ09                  -> sha256.id  si exite el ID entra
#---------------------------------------------------------
#---------------------------------------------------------



def Decision_Tipo_1_1(QR):

    Veri_Impreso = Buscar_Impresos_Tipo_1_1(QR)
    if Veri_Impreso == 0 :
        #Add_Line_End(TAB_USER_TIPO_1_1,QR+'\n')   #Para dispotivos asociados
        QR = QR.replace('-',"")
        #IDQ_Encrip, Resp = Estado_Usuario(IDQ_Encrip,1)
        #print 'Verificar estado del usuario'
        Vector = QR.split(".")
        ID = Vector[1]
        print ID
        ID_1 = Buscar_ID_Tipo1(ID)
        print ID_1
        if ID_1 != -1:
            return -1,'Access granted-E'
    else:
        return -1,'Denegado'

    return -1,'Denegado'
#---------------------------------------------------------
def Buscar_Impresos_Tipo_1_1(QR): #mejorar por que podia pasa cualquiera
    Contador=0
    Usuarios = Get_File(TAB_USER_TIPO_1_1)
    for linea in Usuarios.split('\n'):
        #print linea.count('.')
        if linea.count('.') >=1:
            s=linea.rstrip('\n')
            if 	s ==	QR: Contador +=1
    return Contador
#---------------------------------------------------------
def Guardar_Autorizacion_General_Tipo_1_1(QR, Tiempo_Actual, Pos_linea, Res, Status_Internet):
    global FTQ_Mensajes

    Rest = '0' #    convercion de respuesta  # 0: entrada.1: salida .
    Tipo = '1' #    1: QR

    if      Res == 'Access granted-E':

        Rest = '0' #respuesta
        Dato = QR + '.' + Tiempo_Actual +  '.' + Tipo +  '.' + Rest +  '.' + Status_Internet + '\n'

        if FTQ_Mensajes:
            print 'Registro: ' + Dato

        Add_Line_End(TAB_USER_TIPO_1_1,QR+'\n')   #Para dispotivos asociados
        #--------   Registro generel de autorizaciones para aforo?
        # desavilitado

        return Dato


    elif    Res == 'Access granted-S':

        Rest = '1' #respuesta
        Dato = QR + '.' + Tiempo_Actual +  '.' + Tipo +  '.' + Rest +  '.' + Status_Internet + '\n'
        if FTQ_Mensajes:
            print 'Reguistro: ' + Dato

        Add_Line_End(TAB_USER_TIPO_1_1,QR+'\n')   #Para dispotivos asociados
        #--------   Registro generel de autorizaciones para aforo?
        # desavilitado

        return Dato
#---------------------------------------------------------




#---------------------------------------------------------
#---------------------------------------------------------
#----                   TIPO 1 QR
#---- Formato 1 :         azAZ09. azAZ09                  -> sha256.id  si exite el ID entra
#---------------------------------------------------------
#---------------------------------------------------------



def Decision_Tipo_1(QR):
    Vector = QR.split(".")
    ID = Vector[1]
    #print ID
    ID_1 = Buscar_ID_Tipo1(ID)
    #print ID_1
    if ID_1 != -1:
        #print 'verificar tipo de autorizacion'
        #Pos_linea,Tipo_IO = Buscar_acceso_Tipo1(ID) # desicion sol para el tipo
        Pos_linea,Tipo_IO = Buscar_acceso_Usuario(ID)

        if Pos_linea == -1 :    return -1,'Access granted-E'    # esta el usuario pero no tiene registro
        else:
            if Tipo_IO == '0':      # 0: entrada.1: salida .
                return Pos_linea,'Access granted-S'             # registro de entrada otorga salida
            elif Tipo_IO == '1':    # 0: entrada.1: salida .
                return Pos_linea,'Access granted-E'             # registro de entrada otorga Entrada

        return -1,'Denegado'
    else:
        return -1,'Denegado'
#---------------------------------------------------------
def Buscar_ID_Tipo1(ID_1):  # se puede mejorar la busqueda (busqueda binaria) si la lista esta ordenada
    Usuarios = Get_File(TAB_USER_TIPO_1)
    for linea in Usuarios.split('\n'):
        #print linea.count('.')
        if linea.count('.') >=1:
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")
            #print s2[1]
            if 	ID_1 ==	s2[0]:
                #print 'existe el usuario'
                return s2[0]
    return -1
#---------------------------------------------------------
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
#---------------------------------------------------------
def Buscar_Autorizados_ID_Tipo_1(QR):  # se puede mejorar la busqueda (busqueda binaria) si la lista esta ordenada
    Usuarios = Get_File(TAB_AUTO_TIPO_1)
    ID =QR.split(".")
    ID_1= ID[1]
    Pos_linea=1
    for linea in Usuarios.split('\n'):
        if linea.count('.') >=1:
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")
            #print s2[1]
            if 	ID_1 ==	s2[1]:
                #print 'existe el usuario'
                return Pos_linea
        Pos_linea= 1 + Pos_linea
    return -1
#---------------------------------------------------------
def Guardar_Autorizacion_General_Tipo_1(QR, Tiempo_Actual, Pos_linea, Res, Status_Internet):
    global FTQ_Mensajes

    Rest = '0' #    convercion de respuesta  # 0: entrada.1: salida .
    Tipo = '1' #    1: QR

    if      Res == 'Access granted-E':

        Rest = '0' #respuesta
        Dato = QR + '.' + Tiempo_Actual +  '.' + Tipo +  '.' + Rest +  '.' + Status_Internet + '\n'

        if FTQ_Mensajes:
            print 'Registro: ' + Dato
            print 'Posicion linea: ' + str(Pos_linea)

        #--------   Registro para el dispositivo
        if Pos_linea != -1 :    Update_Line(TAB_AUTO_TIPO_1, Pos_linea, Dato)
        else:                   Add_Line_End(TAB_AUTO_TIPO_1, Dato)

        #--------   Registro generel de autorizaciones para aforo
        # desavilitado
        return Dato

    elif    Res == 'Access granted-S':

        Rest = '1' #respuesta
        Dato = QR + '.' + Tiempo_Actual +  '.' + Tipo +  '.' + Rest +  '.' + Status_Internet + '\n'
        if FTQ_Mensajes:
            print 'Reguistro: ' + Dato
            print 'Posicion linea: ' + str(Pos_linea)

        #--------   Registro en el dispositivo
        if Pos_linea != -1 :    Update_Line(TAB_AUTO_TIPO_1, Pos_linea, Dato)
        else:                   Add_Line_End(TAB_AUTO_TIPO_1, Dato)

        #--------   Registro generel de autorizaciones para aforo
        # desavilitado
        return Dato
#---------------------------------------------------------
def Guardar_Autorizacion_Dispo_Tipo_1(QR, Tiempo_Actual, Pos_linea, Res, Status_Internet):# NO se utiliza
    global FTQ_Mensajes

    Rest = '0' #    convercion de respuesta  # 0: entrada.1: salida .
    Tipo = '1' #    1: QR

    if      Res == 'Access granted-E':

        Rest = '0' #respuesta
        Dato = QR + '.' + Tiempo_Actual +  '.' + Tipo +  '.' + Rest +  '.' + Status_Internet + '\n'

        if FTQ_Mensajes:
            print 'Registro: ' + Dato
            print 'Posicion linea: ' + str(Pos_linea)

        #--------   registro  para el counter
        Enviar_Autorizado_Counter(Dato)


        #--------   Registro para el dispositivo
        if Pos_linea != -1 :    Update_Line(TAB_AUTO_TIPO_1, Pos_linea, Dato)
        else:                   Add_Line_End(TAB_AUTO_TIPO_1, Dato)

        #--------   Registro generel para envio al servidor
        Add_Line_End(TAB_ENV_SERVER, Dato)#para envio al servidor revisar la habilitacion


        #--------   Registro generel de autorizaciones para aforo
        # desavilitado

    elif    Res == 'Access granted-S':

        Rest = '1' #respuesta
        Dato = QR + '.' + Tiempo_Actual +  '.' + Tipo +  '.' + Rest +  '.' + Status_Internet + '\n'
        if FTQ_Mensajes:
            print 'Reguistro: ' + Dato
            print 'Posicion linea: ' + str(Pos_linea)

        #--------   registor  para el counter
        Enviar_Autorizado_Counter(Dato)

        #--------   Registro en el dispositivo
        if Pos_linea != -1 :    Update_Line(TAB_AUTO_TIPO_1, Pos_linea, Dato)
        else:                   Add_Line_End(TAB_AUTO_TIPO_1, Dato)

        #--------   Registro generel para envio al servidor
        Add_Line_End(TAB_ENV_SERVER, Dato)#para envio al servidor revisar la habilitacion

#---------------------------------------------------------

# busquedas para un tipo de usuario con multips tipos de acceso qr,tag nfc

#---------------------------------------------------------
def Buscar_acceso_Usuario(ID):
    Usuarios = Get_File(TAB_USER_AUTO)
    Pos_linea=1  # comiensa en 1 para conpenzar la linea cero
    for linea in Usuarios.split('\n'):
        if linea.count('.') >=1:
            #print linea
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")
            if 	ID ==	s2[0]:      return Pos_linea, s2[1] # retorno el estado y linea del usuarios
        Pos_linea= 1 + Pos_linea
    return -1,-1
#-----------------

def Guardar_Autorizacion_Usuario_Tipos(Tipo, QR, Res, Status_Internet):# para multiples tipos qr,tg,etc
    global FTQ_Mensajes

    Rest = '0' #    convercion de respuesta  # 0: entrada.1: salida .
    Dato = ''
    ID =  ''
    Pos_Linea =-1

    if      Tipo == 'T1':
        s2 =QR.split('.')
        ID = s2[1] #QR + '.' + Tiempo_Actual +  '.' + Tipo +  '.' + Rest +  '.' + Status_Internet + '\n'
    elif    Tipo == 'TECLADO':
        ID = QR
    elif    Tipo == 'NFC':
        ID = QR

    #print 'ID: ' + ID
    Pos_Linea, I_0 = Buscar_acceso_Usuario(ID)

    #print 'Pos: ' + str(Pos_Linea)
    #print 'I_0: ' + str(I_0)

    if      Res == 'Access granted-E':  Dato = ID + '.0' + '\n'
    elif    Res == 'Access granted-S':  Dato = ID + '.1' + '\n'

    if FTQ_Mensajes:   print 'Dato: ' + Dato

    #--------   Registro para tipos de acceso
    if Pos_Linea != -1 :    Update_Line(TAB_USER_AUTO, Pos_Linea, Dato)
    else:                   Add_Line_End(TAB_USER_AUTO, Dato)


#---------------------------------------------------------


        #--------   Registro generel de autorizaciones para aforo
        # desavilitado
#---------------------------------------------------------
#---------------------------------------------------------
#----                   TIPO 2 QR
#---- Formato 2 :         azAZ09. azAZ09. 09              -> sha256.id.tiempo ventana quemado 60 minutos
#---------------------------------------------------------
#---------------------------------------------------------
def Decision_Tipo_2(QR, Tiempo_Actual):
    global FTQ_Mensajes
    Vector = QR.split(".")
    ID = Vector[1]
    #print ID
    ID_1 = Buscar_ID_Tipo2(ID)
    #print ID_1
    Ventana = Ventana_tiempo_Tipo_2(QR, Tiempo_Actual)
    print Ventana
    if Ventana != -1:
        if ID_1 != -1:
            #print 'verificar tipo de autorizacion'
            Pos_linea,Tipo_IO =Buscar_acceso_Tipo2(ID)
            if Pos_linea == -1 :    return -1,'Access granted-E'    # esta el usuario pero no tiene registro
            else:
                if Tipo_IO == '0':      # 0: entrada.1: salida .
                    return Pos_linea,'Access granted-S'             # registro de entrada otorga salida
                elif Tipo_IO == '1':    # 0: entrada.1: salida .
                    return Pos_linea,'Access granted-E'             # registro de entrada otorga Entrada

            return -1,'Denegado'
        else:
            return -1,'Denegado'
    else:
        if FTQ_Mensajes: print 'Fuera del rango' #revizar si esta dentro dar salida
        if ID_1 != -1:
            #print 'verificar tipo de autorizacion'
            Pos_linea,Tipo_IO =Buscar_acceso_Tipo2(ID)
            if Pos_linea == -1 :    return -1,'Denegado'            #
            else:
                if Tipo_IO == '0':      # 0: entrada.1: salida .
                    return Pos_linea,'Access granted-S'             # registro de entrada otorga salida
                elif Tipo_IO == '1':    # 0: entrada.1: salida .
                    return -1,'Denegado'

            return -1,'Denegado'
        else:
            return -1,'Denegado'

    return -1,'Denegado'
#---------------------------------------------------------
def Buscar_ID_Tipo2(ID_1):  # se puede mejorar la busqueda (busqueda binaria) si la lista esta ordenada
    Usuarios = Get_File(TAB_USER_TIPO_2)
    for linea in Usuarios.split('\n'):
        #print linea.count('.')
        if linea.count('.') >=1:
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")
            #print s2[1]
            if 	ID_1 ==	s2[0]:
                #print 'existe el usuario'
                return s2[0]
    return -1
#---------------------------------------------------------
def Buscar_acceso_Tipo2(ID_1):
    Usuarios = Get_File(TAB_AUTO_TIPO_2)
    Pos_linea=1  # comiensa en 1 para convenzar la linea cero
    for linea in Usuarios.split('\n'):
        if linea.count('.') >=1:
            #print linea
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")
            #print s2[5]
            if 	ID_1 ==	s2[5]:      return Pos_linea, s2[5] # retorno el estado y linea del usuarios
        Pos_linea= 1 + Pos_linea
    return -1,-1
#---------------------------------------------------------
def Buscar_Autorizados_ID_Tipo_2(QR):  # se puede mejorar la busqueda (busqueda binaria) si la lista esta ordenada
    Usuarios = Get_File(TAB_AUTO_TIPO_2)
    ID =QR.split(".")
    ID_1= ID[1]
    Pos_linea=1
    for linea in Usuarios.split('\n'):
        if linea.count('.') >=1:
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")
            print s2[1]
            if 	ID_1 ==	s2[1]:
                #print 'existe el usuario'
                return Pos_linea
        Pos_linea= 1 + Pos_linea
    return -1
#---------------------------------------------------------
def Ventana_tiempo_Tipo_2(QR, Tiempo_Actual):
    #-------  ventana de tiempo 60 minutos
    Vector = QR.split(".")
    Tiempo_inicio = int(float(Vector[2])/1000)
    T_A           = int(float(Tiempo_Actual)/1000)
    Tiempo_fin    = int(float(Vector[2])/1000) + (900*4)  # 900 = 15   -> 60 mimutos 900*4
    #print 'T inicio:' + str( datetime.datetime.fromtimestamp(Tiempo_inicio))
    #print 'T Actual:' + str( datetime.datetime.fromtimestamp(T_A))
    #print 'T Fin   :' + str( datetime.datetime.fromtimestamp(Tiempo_fin))
    if (Tiempo_inicio <= T_A) and (T_A <= Tiempo_fin):  return 1
    else:                                               return -1
#---------------------------------------------------------
def Guardar_Autorizacion_General_Tipo_2(QR, Tiempo_Actual, Pos_linea, Res, Status_Internet):
    global FTQ_Mensajes

    Rest = '0' #    convercion de respuesta  # 0: entrada.1: salida .
    Tipo = '1' #    1: QR

    if      Res == 'Access granted-E':

        Rest = '0' #respuesta
        Dato = QR + '.' + Tiempo_Actual +  '.' + Tipo +  '.' + Rest +  '.' + Status_Internet + '\n'

        if FTQ_Mensajes:
            print 'Registro: ' + Dato
            print 'Posicion linea: ' + str(Pos_linea)

        #--------   registro  para el counter
        #Enviar_Autorizado_Counter(Dato)

        #--------   Registro para el dispositivo
        if Pos_linea != -1 :    Update_Line(TAB_AUTO_TIPO_2, Pos_linea, Dato)
        else:                   Add_Line_End(TAB_AUTO_TIPO_2, Dato)

        #--------   Registro generel para envio al servidor
        #Add_Line_End(TAB_ENV_SERVER, Dato)#para envio al servidor revisar la habilitacion

        #--------   Registro generel de autorizaciones para aforo
        # desavilitado
        return Dato

    elif    Res == 'Access granted-S':

        Rest = '1' #respuesta
        Dato = QR + '.' + Tiempo_Actual +  '.' + Tipo +  '.' + Rest +  '.' + Status_Internet + '\n'
        if FTQ_Mensajes:
            print 'Reguistro: ' + Dato
            print 'Posicion linea: ' + str(Pos_linea)

        #--------   registor  para el counter
        #Enviar_Autorizado_Counter(Dato)

        #--------   Registro en el dispositivo
        if Pos_linea != -1 :    Update_Line(TAB_AUTO_TIPO_2, Pos_linea, Dato)
        else:                   Add_Line_End(TAB_AUTO_TIPO_2, Dato)

        #--------   Registro generel para envio al servidor
        #Add_Line_End(TAB_ENV_SERVER, Dato)#para envio al servidor revisar la habilitacion

        #--------   Registro generel de autorizaciones para aforo
        # desavilitado
        return Dato

#---------------------------------------------------------
def Guardar_Autorizacion_Dispo_Tipo_2(QR, Tiempo_Actual, Pos_linea, Res, Status_Internet):
    global FTQ_Mensajes

    Rest = '0' #    convercion de respuesta  # 0: entrada.1: salida .
    Tipo = '1' #    1: QR

    if      Res == 'Access granted-E':

        Rest = '0' #respuesta
        Dato = QR + '.' + Tiempo_Actual +  '.' + Tipo +  '.' + Rest +  '.' + Status_Internet + '\n'

        if FTQ_Mensajes:
            print 'Registro: ' + Dato
            print 'Posicion linea: ' + str(Pos_linea)

        #--------   registro  para el counter
        Enviar_Autorizado_Counter(Dato)

        #--------   Registro para el dispositivo
        if Pos_linea != -1 :    Update_Line(TAB_AUTO_TIPO_2, Pos_linea, Dato)
        else:                   Add_Line_End(TAB_AUTO_TIPO_2, Dato)

        #--------   Registro generel para envio al servidor
        Add_Line_End(TAB_ENV_SERVER, Dato)#para envio al servidor revisar la habilitacion

        #--------   Registro generel de autorizaciones para aforo
        # desavilitado

    elif    Res == 'Access granted-S':

        Rest = '1' #respuesta
        Dato = QR + '.' + Tiempo_Actual +  '.' + Tipo +  '.' + Rest +  '.' + Status_Internet + '\n'
        if FTQ_Mensajes:
            print 'Reguistro: ' + Dato
            print 'Posicion linea: ' + str(Pos_linea)

        #--------   registor  para el counter
        Enviar_Autorizado_Counter(Dato)

        #--------   Registro en el dispositivo
        if Pos_linea != -1 :    Update_Line(TAB_AUTO_TIPO_2, Pos_linea, Dato)
        else:                   Add_Line_End(TAB_AUTO_TIPO_2, Dato)

        #--------   Registro generel para envio al servidor
        Add_Line_End(TAB_ENV_SERVER, Dato)#para envio al servidor revisar la habilitacion

        #--------   Registro generel de autorizaciones para aforo
        # desavilitado

#---------------------------------------------------------
#---------------------------------------------------------
#----                   TIPO 2_1 QR
#---- Formato 2.1 :       azAZ09. azAZ09. 09. 09          -> sha256.id.tiempo init.tiempo fin.
#---------------------------------------------------------
#---------------------------------------------------------
def Decision_Tipo_2_1(QR, Tiempo_Actual):
    global FTQ_Mensajes
    Vector = QR.split(".")
    ID = Vector[1]
    #print ID
    ID_1 = Buscar_ID_Tipo2_1(ID)
    #print ID_1
    Ventana = Ventana_tiempo_Tipo_2_1(QR, Tiempo_Actual)
    #print Ventana

    if Ventana != -1:
        if ID_1 != -1:

            #print 'verificar tipo de autorizacion'
            Pos_linea,Tipo_IO =Buscar_acceso_Tipo2_1(ID)
            if Pos_linea == -1 :    return -1,'Access granted-E'    # esta el usuario pero no tiene registro
            else:
                if Tipo_IO == '0':      # 0: entrada.1: salida .
                    return Pos_linea,'Access granted-S'             # registro de entrada otorga salida
                elif Tipo_IO == '1':    # 0: entrada.1: salida .
                    return Pos_linea,'Access granted-E'             # registro de entrada otorga Entrada

            return -1,'Denegado'
        else:
            return -1,'Denegado'
    else:
        if FTQ_Mensajes: print 'Fuera del rango' #revizar si esta dentro dar salida
        if ID_1 != -1:

            #print 'verificar tipo de autorizacion'
            Pos_linea,Tipo_IO =Buscar_acceso_Tipo2_1(ID)
            if Pos_linea == -1 :    return -1,'Denegado'            #
            else:
                if Tipo_IO == '0':      # 0: entrada.1: salida .
                    return Pos_linea,'Access granted-S'             # registro de entrada otorga salida
                elif Tipo_IO == '1':    # 0: entrada.1: salida .
                    return -1,'Denegado'

            return -1,'Denegado'
        else:
            return -1,'Denegado'


    return -1,'Denegado'
#---------------------------------------------------------
def Buscar_ID_Tipo2_1(ID_1):  # se puede mejorar la busqueda (busqueda binaria) si la lista esta ordenada
    Usuarios = Get_File(TAB_USER_TIPO_2_1)
    for linea in Usuarios.split('\n'):
        #print linea.count('.')
        if linea.count('.') >=1:
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")
            #print s2[1]
            if 	ID_1 ==	s2[1]:
                #print 'existe el usuario'
                return s2[1]
    return -1
#---------------------------------------------------------
def Buscar_Autorizados_ID_Tipo_2_1(QR):  # se puede mejorar la busqueda (busqueda binaria) si la lista esta ordenada
    Usuarios = Get_File(TAB_AUTO_TIPO_2_1)
    ID =QR.split(".")
    ID_1= ID[1]
    Pos_linea=1
    for linea in Usuarios.split('\n'):
        if linea.count('.') >=1:
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")
            if 	ID_1 ==	s2[1]:
                #print 'existe el usuario'
                return Pos_linea
        Pos_linea= 1 + Pos_linea
    return -1
#---------------------------------------------------------
def Buscar_acceso_Tipo2_1(ID_1):
    Usuarios = Get_File(TAB_AUTO_TIPO_2_1)
    Pos_linea=1  # comiensa en 1 para convenzar la linea cero
    for linea in Usuarios.split('\n'):
        if linea.count('.') >=1:
            #print linea
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")
            print s2[6]
            if 	ID_1 ==	s2[1]:      return Pos_linea, s2[6] # retorno el estado y linea del usuarios
        Pos_linea= 1 + Pos_linea
    return -1,-1
#---------------------------------------------------------
def Ventana_tiempo_Tipo_2_1(QR, Tiempo_Actual):
    #-------  ventana de tiempo 60 minutos
    Vector = QR.split(".")
    Tiempo_inicio = int(float(Vector[2])/1000)
    T_A           = int(float(Tiempo_Actual)/1000)
    Tiempo_fin    = int(float(Vector[3])/1000)# + (900*4)  # 900 = 15   -> 60 mimutos 900*4
    #print 'T inicio:' + str( datetime.datetime.fromtimestamp(Tiempo_inicio))
    #print 'T Actual:' + str( datetime.datetime.fromtimestamp(T_A))
    #print 'T Fin   :' + str( datetime.datetime.fromtimestamp(Tiempo_fin))
    if (Tiempo_inicio <= T_A) and (T_A <= Tiempo_fin):  return 1
    else:                                               return -1
#---------------------------------------------------------
def Guardar_Autorizacion_General_Tipo_2_1(QR, Tiempo_Actual, Pos_linea, Res, Status_Internet):
    global FTQ_Mensajes

    Rest = '0' #    convercion de respuesta  # 0: entrada.1: salida .
    Tipo = '1' #    1: QR

    if      Res == 'Access granted-E':

        Rest = '0' #respuesta
        Dato = QR + '.' + Tiempo_Actual +  '.' + Tipo +  '.' + Rest +  '.' + Status_Internet + '\n'

        if FTQ_Mensajes:
            print 'Registro: ' + Dato
            print 'Posicion linea: ' + str(Pos_linea)

        #--------   registro  para el counter
        #Enviar_Autorizado_Counter(Dato)

        #--------   Registro para el dispositivo
        if Pos_linea != -1 :    Update_Line(TAB_AUTO_TIPO_2_1, Pos_linea, Dato)
        else:                   Add_Line_End(TAB_AUTO_TIPO_2_1, Dato)

        #--------   Registro generel para envio al servidor
        #Add_Line_End(TAB_ENV_SERVER, Dato)#para envio al servidor revisar la habilitacion

        #--------   Registro generel de autorizaciones para aforo
        # desavilitado
        return Dato

    elif    Res == 'Access granted-S':

        Rest = '1' #respuesta
        Dato = QR + '.' + Tiempo_Actual +  '.' + Tipo +  '.' + Rest +  '.' + Status_Internet + '\n'
        if FTQ_Mensajes:
            print 'Reguistro: ' + Dato
            print 'Posicion linea: ' + str(Pos_linea)

        #--------   registor  para el counter
        #Enviar_Autorizado_Counter(Dato)

        #--------   Registro en el dispositivo
        if Pos_linea != -1 :    Update_Line(TAB_AUTO_TIPO_2_1, Pos_linea, Dato)
        else:                   Add_Line_End(TAB_AUTO_TIPO_2_1, Dato)

        #--------   Registro generel para envio al servidor
        #Add_Line_End(TAB_ENV_SERVER, Dato)#para envio al servidor revisar la habilitacion

        #--------   Registro generel de autorizaciones para aforo
        # desavilitado
        return Dato

#---------------------------------------------------------
def Guardar_Autorizacion_Dispo_Tipo_2_1(QR, Tiempo_Actual, Pos_linea, Res, Status_Internet):
    global FTQ_Mensajes

    Rest = '0' #    convercion de respuesta  # 0: entrada.1: salida .
    Tipo = '1' #    1: QR

    if      Res == 'Access granted-E':

        Rest = '0' #respuesta
        Dato = QR + '.' + Tiempo_Actual +  '.' + Tipo +  '.' + Rest +  '.' + Status_Internet + '\n'

        if FTQ_Mensajes:
            print 'Registro: ' + Dato
            print 'Posicion linea: ' + str(Pos_linea)

        #--------   registro  para el counter
        Enviar_Autorizado_Counter(Dato)

        #--------   Registro para el dispositivo
        if Pos_linea != -1 :    Update_Line(TAB_AUTO_TIPO_2_1, Pos_linea, Dato)
        else:                   Add_Line_End(TAB_AUTO_TIPO_2_1, Dato)

        #--------   Registro generel para envio al servidor
        Add_Line_End(TAB_ENV_SERVER, Dato)#para envio al servidor revisar la habilitacion

        #--------   Registro generel de autorizaciones para aforo
        # desavilitado

    elif    Res == 'Access granted-S':

        Rest = '1' #respuesta
        Dato = QR + '.' + Tiempo_Actual +  '.' + Tipo +  '.' + Rest +  '.' + Status_Internet + '\n'
        if FTQ_Mensajes:
            print 'Reguistro: ' + Dato
            print 'Posicion linea: ' + str(Pos_linea)

        #--------   registor  para el counter
        Enviar_Autorizado_Counter(Dato)

        #--------   Registro en el dispositivo
        if Pos_linea != -1 :    Update_Line(TAB_AUTO_TIPO_2_1, Pos_linea, Dato)
        else:                   Add_Line_End(TAB_AUTO_TIPO_2_1, Dato)

        #--------   Registro generel para envio al servidor
        Add_Line_End(TAB_ENV_SERVER, Dato)#para envio al servidor revisar la habilitacion

        #--------   Registro generel de autorizaciones para aforo
        # desavilitado

#---------------------------------------------------------
#---------------------------------------------------------
#----                   TIPO 3 QR
#---- Formato 3 :         3. azAZ09. azAZ09. azAZ09. 09  -> tipo.id.id.id.tiempo init.   tiken multiples Usuarios
#---------------------------------------------------------
#---------------------------------------------------------
def Decision_Tipo_3(QR):

    global FTQ_Mensajes
    Vector = QR.split(".")
    ID =  Vector[1] + '.' + Vector[2]+ '.' + Vector[3]
    print ID
    Pos_L,Max_In,Actuales_In = Buscar_ID_Tipo3(ID)

    #print Pos_L
    #print Max_In
    #print Actuales_In
    #print 'incremento'
    Incre = int(Actuales_In)+1
    #print Incre

    if Pos_L != -1:
        #print 'verificar contidad de autorizaciones autorizacion'
        if Actuales_In < Max_In:    return Pos_L,'Access granted-E',str(Incre)
        else:                       return -1,'Denegado',-1
    else:                           return -1,'Denegado',-1
#---------------------------------------------------------
def Ventana_tiempo_Tipo_3(QR, Tiempo_Actual):

    Tiempo_Max=3600*24     #quemado 60 minutos   3600 segundos *24
    Vector = QR.split(".")
    T_inicio = int(Vector[4])

    if Tiempo_Actual > T_inicio :
        Resta = (int(Tiempo_Actual) -int(Vector[4]))/1000
        #print Resta
        if Resta >=Tiempo_Max : return -1
        else:                   return 1
#---------------------------------------------------------
def Buscar_ID_Tipo3(ID_1):  # se puede mejorar la busqueda (busqueda binaria) si la lista esta ordenada
    Pos_linea=1  # comnesae en 1 para convenzar la linea cero
    Usuarios = Get_File(TAB_USER_TIPO_3)
    for linea in Usuarios.split('\n'):
        if linea.count('.') >=1:
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")
            ID =  s2[0] + '.' + s2[1]+ '.' + s2[2]
            if 	ID_1 ==	ID:
                print 'existe el usuario'
                #print s2[2]
                #print s2[3]
                return Pos_linea, s2[2], s2[3]

            Pos_linea= 1 + Pos_linea

    return -1,-1,-1
#---------------------------------------------------------
def Guardar_Autorizacion_Tipo_3(usuario):

    puntos = usuario.count(".")
    if puntos == 9:
        Add_File(TAB_AUTO_TIPO_3, usuario+'\n')
        s = usuario.split(".")
        ID_1 = s[1] + '.' + s[2] + '.' + s[3]
        Usuarios = Get_File(TAB_USER_TIPO_3)
        newUsuarios = ""
        isFirst=True
        for linea in Usuarios.split('\n'):
            if linea.count('.') >= 1:
                ticket = linea.rstrip('\n')
                ticket = ticket.rstrip('\r')
                s2 = ticket.split(".")
                ID = s2[0] + '.' + s2[1] + '.' + s2[2]
                if ID_1 == ID and isFirst:
                    if(int(s[-1])<int(s[3])):
                        newUsuarios += s[1] + '.' + s[2] + '.' + s[3] + '.' + s[-1] + "\n"
                    isFirst=False
                else:
                    newUsuarios += linea + "\n"
        Clear_File(TAB_USER_TIPO_3)
        Add_File(TAB_USER_TIPO_3, newUsuarios)

        #--------   Registro generel para envio al servidor
        #Add_Line_End(TAB_ENV_SERVER, Dato)#para envio al servidor revisar la habilitacion
        #Enviar_Autorizado_Counter(usuario)

    else:
        print 'No cumple parametros'
#---------------------------------------------------------
def Enviar_QR_Tipo3_Counter(QR, Tiempo_Actual):
    global FTQ_Mensajes
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
                            if Accion_res[1] != "-1":
                                # print QR
                                Guardar_Autorizacion_Tipo_3(QR + "." + Tiempo_Actual + ".1.0.1." + Accion_res[1])
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
#---------------------------------------------------------




#---------------------------------------------------------
#---------------------------------------------------------
#-------            Envios genelares de informacion a counter o servidor
#---------------------------------------------------------
#---------------------------------------------------------

def Enviar_QR_Counter(QR, Tiempo_Actual):
    global FTQ_Mensajes
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
                    if FTQ_Mensajes:    print 'Respuesta :'
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
                            if FTQ_Mensajes:
                                print 'Tipo: ' + Accion_res[0]
                                print 'Contador:' + Accion_res[1]

                            Clear_File(CONT_RECEIVED_DATA_PATH)
                            Clear_File(CONT_RECEIVED_FLAG_PATH)
                            return Accion_res[0], Accion_res[1]

                        else:
                            if FTQ_Mensajes:
                                print 'Es otra comunicacion'

                if T_Antes == -1:
                    T_E = int(time.time()*1000.0)  # Tiempo
                    T_Antes = T_E
                else:
                    T_E = int(time.time()*1000.0)  # Tiempo
                Tiempo_diferencia = T_E - T_Antes
                # print str(Tiempo_diferencia)
                if Tiempo_diferencia >= 2000:
                    if FTQ_Mensajes:    print 'procesar por no respuesta T:' + str(Tiempo_diferencia)
                    Clear_File(CONT_SEND_DATA_PATH)
                    Clear_File(CONT_SEND_FLAG_PATH)
                    Clear_File(CONT_RECEIVED_DATA_PATH)
                    Clear_File(CONT_RECEIVED_FLAG_PATH)
                    return 'Error',"-1"
        if int(time.time()*1000.0)-Flag_Revision_Time > 1000:
            break
    if FTQ_Mensajes:    print 'Error en la comunicacion : Flag No vacio'
    return 'Error',"-1"
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

def Enviar_Autorizado_Server(Dato):
    #--------   Registro generel para envio al servidor
    Add_Line_End(TAB_ENV_SERVER, Dato)  # para envio al servidor
