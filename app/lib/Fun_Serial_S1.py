#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Libreria personal para procesar un qr.




# ideas a implementar




# dmesg | grep tty
"""
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------

import commands
import serial
import os, time


from serial import SerialException

#---------------------------------
#           Librerias personales
#---------------------------------

from Lib_File import *            # importar con los mismos nombres
from Lib_Rout import *            # importar con los mismos nombres


#-----------------------------------------------------------
#                       CONSTANTES
#-----------------------------------------------------------

FS_Mensajes     = 0               # 0: NO print  1: Print
Puerto_Serial   = '/dev/ttyUSB1'  # '/dev/ttyS0'
Lectora         = 'QR600-VHK-E'   # Tipo de lectora
Port            = 0               # Clase del serial

#-----------------------------------------------------------
#                       Variables
#-----------------------------------------------------------

TAG_NFC =''              # guardado de qr valido
TAG_NFC_antes =''        # QR anterior

T_Nuev_TAG   = 0
T_Repe_TAG   = 0
T_Maximo_TAG = 7



QR =''              # guardado de qr valido
QR_antes =''        # QR anterior

T_Maximo = 7        # timepo maximo para verificar un repetido para tipo  3 o tiket
T_Nuev_QR = 0       # timepo de inicioa de un nuevo qr
T_Repe_QR = 0       # timepo de inicioa de un nuevo qr

TECLAS =''              # guardado de qr valido
TECLAS_antes =''        # QR anterior


#---------------------------------------------------------
#---------------------------------------------------------
#----       funciones del serial
#---------------------------------------------------------
#---------------------------------------------------------

#---------------------------------------------------------
def Iniciar_Serial():

    global Port, FS_Mensajes, Puerto_Serial
    Intentos = 0

    while 1:

        try :

            time.sleep(2.05) # Tiempo de reintentos
            Port = serial.Serial(Puerto_Serial, baudrate=115200, timeout=1)

        except SerialException:

            Intentos = Intentos + 1
            if Intentos >= 10:  return 0
            if FS_Mensajes: print 'Error'

        if (type(Port) is serial.serialposix.Serial):
            if FS_Mensajes: print 'Puerto Abierto.'

            return 1

#---------------------------------------------------------
def Transmitir_Datos():

    global Port, FS_Mensajes, Puerto_Serial, Lectora
    #TX_datos_hex('Peticion')

    if Lectora == 'QR600-VHK-E'  :

        #if FS_Mensajes: print 'Transmitir_Datos'
        TX_QR600_VHK_E ()

    elif    Lectora == 'QR600'   :
        if FS_Mensajes: print 'NO Resive'
    else                        :
        if FS_Mensajes: print 'NO Resive'


#---------------------------------------------------------
def Recivir_Datos():

    global Port, FS_Mensajes, Puerto_Serial


    rcv = Port.read(250)
    T_rcv = len(rcv)
    if T_rcv >= 1:
        #if FS_Mensajes: print 'Datos RX:' + str(rcv)
        #Procesar_Datos_Hex(rcv)
        if Lectora == 'QR600-VHK-E'  :
            Procesar_RX_QR600_VHK_E(rcv)
        elif    Lectora == 'QR600'   :
            if FS_Mensajes: print 'NO Resive'
        else                        :
            if FS_Mensajes: print 'NO Resive'


#---------------------------------------------------------
def Datos_Serial():

    global Port, FS_Mensajes, Puerto_Serial

    while True:
        try :

            Transmitir_Datos()
            Recivir_Datos()

        except SerialException:
                if Iniciar_Serial() == 0:
                    if FS_Mensajes: print 'Serando el proceso por fallo grave en el Puerto'
                    break;









#---------------------------------------------------------
#----       Funciones para el QR600-VHK-E
#---------------------------------------------------------

#---------------------------------------------------------
def Trama_TX_QR600_VHK_E(Tipo):

    Trama = "\xaa\x01\x97\x01\x00\x07\x01\xb6" #default
    if Tipo == 'Peticion':  Trama = "\xaa\x01\x97\x01\x00\x07\x01\xb6"
    elif Tipo == 'Verde':   Trama = "\xaa\x01\x98\x01\x00\x00\x43\x60"
    elif Tipo == 'Rojo':    Trama = "\xaa\x01\x98\x01\x00\xfe\xc2\xe0"

    return Trama
#---------------------------------------------------------
def TX_QR600_VHK_E ():

    global Port, FS_Mensajes

    data = Trama_TX_QR600_VHK_E('Peticion')
    Port.write(data)

#---------------------------------------------------------
def Procesar_RX_QR600_VHK_E(rcv):

    global Port, FS_Mensajes

    Estado = 0
    Dato =''

    #if FS_Mensajes: print 'Resicion _Datos TX_QR600_VHK_E'

    if len(rcv) > 0:
        if (rcv.find('<') != -1 ) and (rcv.find('>') != -1) :
            #print rcv.find('<')
            #print rcv.find('>')
            ES_QR = rcv[rcv.find('<'): rcv.find('>')+1]
            #print 'QR: ' + ES_QR
            Estado = 4
            Dato =ES_QR

        else:
            Dato_Hex = Convertir_Datos_Hex(rcv)
            #if FS_Mensajes: print 'Datos RX_HEX:' + Dato_Hex
            Estado, Dato = Analisis_Trama_RX__QR600_VHK_E(Dato_Hex)


        if Estado != 0 and Estado != 1:
                if FS_Mensajes: print 'Resultado: ' + str(Estado) + ', ' + str (Dato)

                if      Estado == 2:    Decision_Tag( str(Dato) )
                elif    Estado == 3:    Decision_Teclado(Dato)
                elif    Estado == 4:    Decision_Qr(Dato)







#---------------------------------------------------------------------------------------

def Analisis_Trama_RX__QR600_VHK_E(Tag_data):
    if len(Tag_data) > 0:
        #print Tag_data[0:5]
        #print Tag_data.find(' aa 1')
        #print 'Cadena balida: '+ Tag_data[Tag_data.find(' aa 1'):]
        if Tag_data.find(' aa 1') > -1:
            Tag_data = Tag_data[Tag_data.find(' aa 1'):]


        if ' aa 1' in Tag_data[0:5]:
            if ' aa 1 97 1 0 7 1 b6'        in Tag_data:
                #print 'Peticion      : ' + Tag_data
                return 1, ""
            elif ' aa 1 c9 1 0 0 53 9c'  in Tag_data:
                #print 'Rx sin Nada   : ' + Tag_data
                return 1, ""
            elif ' aa 1 c8 '                in Tag_data:
                #print 'Datos         : ' + Tag_data
                Datos = Tag_data.split(" ")
                Tipo = int(Datos[7])
                #print 'Tipo          : ' + str(Tipo)
                if Tipo == 2:
                    #covercion de formato de hex a decimal
                    Numero =""
                    for i in range(9 + int(Datos[8],base=16), 9, -1):  Numero += Datos[i]
                    #print 'Tag o Targeta :'+ str(int(Numero,base=16))
                    Decimal = int(Numero,base=16)
                    return 2, Decimal
                    #TX_datos_hex('Verde')
                elif Tipo == 3:
                    #covercion de formato de desima a anssi numerico
                    Numero =""
                    for i in range(10, 10 + int(Datos[8],base=16)):  Numero += str(int(Datos[i])-30)

                    #print 'Teclado   : ' + Numero
                    return 3, Numero
                    #TX_datos_hex('Verde')
                else:
                    #print 'No definido  : ' + Tag_data
                    #TX_datos_hex('Rojo')
                    return 0, ""

            else:
                #print 'Otras      : ' + Tag_data
                return 0, ""

    return 0, ""












#---------------------------------------------------------
#----       Funciones para tratamiento de informacion global
#---------------------------------------------------------

def Convertir_Datos_Hex(Dato):

    Tag_data =""
    for letra in Dato:
        datohex = hex(ord(letra))
        Tag_data += datohex.replace('0x'," ")

    return Tag_data



#---------------------------------------------------------------------------------------

def Decision_Teclado(Teclado):

    #if SQ_Mensajes: print 'TC:'+ Teclado
    Guardar_Teclado(Teclado)
    Activar_Teclado()

#---------------------------------------------------------------------------------------

def Decision_Tag(Tag):

    global TAG_NFC, TAG_NFC_antes, T_Nuev_TAG, T_Repe_TAG, T_Maximo_TAG


    TAG_NFC = Tag
    #print Tag
    if TAG_NFC != TAG_NFC_antes:
        TAG_NFC_antes = TAG_NFC
        #print 'uuu'
        Guardar_Tag(TAG_NFC)
        Activar_Tag()
        """
        if 'TN:' in TAG_NFC:
            if SQ_Mensajes: print 'TN:'+ TAG_NFC
            Guardar_Tag(TAG_NFC)
            Activar_Tag()
        elif 'TR:' in TAG_NFC:
            if SQ_Mensajes: print 'TR:'+ TAG_NFC
            #Set_File(STATUS_REPEAT_NFC, '2')    # Estado QR repetido
            Guardar_Tag(TAG_NFC)
            Activar_Tag()
        """
    else:
        #T_Nuev_TAG, T_Repe_TAG, T_Maximo_TAG
        T_Repe_TAG = time.time()
        T_transcurido = int(T_Repe_TAG-T_Nuev_TAG)
        #print 'T_Diferencia: ' + str(T_transcurido)
        if T_transcurido >= T_Maximo_TAG :
            T_Nuev_TAG = T_Repe_TAG = time.time()
            Guardar_Tag(TAG_NFC)
            Activar_Tag()
            """
            if 'TN:' in TAG_NFC:
                if SQ_Mensajes: print 'TN:'+ TAG_NFC
                Guardar_Tag(TAG_NFC)
                Activar_Tag()

            elif 'TR:' in TAG_NFC:
                if SQ_Mensajes: print 'TR:'+ TAG_NFC
                #Set_File(STATUS_REPEAT_NFC, '2')    # Estado QR repetido
                Guardar_Tag(TAG_NFC)
                Activar_Tag()
            """

        else:
            #Set_File(COM_BUZZER,'1')       #sonido eliminar si no es necesario
            if FS_Mensajes: print 'Repetido'
            #Set_File(STATUS_REPEAT_QR, '2')    # Estado QR repetido






#---------------------------------------------------------------------------------------

def Decision_Qr(x):
    global FS_Mensajes, QR, QR_antes, T_Nuev_QR, T_Repe_QR, T_Maximo
    #--------- QR repetido
    QR = x
    if QR != QR_antes:
        QR_antes = QR
        T_Nuev_QR = time.time()
        if FS_Mensajes: print 'Nuevo: ' + QR
        Guardar_QR()
        Activar_QR()
    else:
        #print 'Repetido:' + x + ' , Estado Valido: ' + str(Valido)
        T_Repe_QR = time.time()
        T_transcurido = int(T_Repe_QR-T_Nuev_QR)
        #print 'T_Diferencia: ' + str(T_transcurido)
        if T_transcurido >= T_Maximo :
            T_Nuev_QR = T_Repe_QR = time.time()
            #Nueva_Avilitacion_portiempo_y_Tipo()
        else:
            if FS_Mensajes: print 'Repetido'
            #Set_File(STATUS_REPEAT_QR, '2')    # Estado QR repetido

        #print 'T_Nuevo:' + str(T_Nuev_QR) + ' , T_Repetido:' + str(T_Repe_QR) + ', T_Diferencia: ' + str(int(T_Repe_QR-T_Nuev_QR))





#---------------------------------------------------------------------------------------

def Activar_QR():
    global QR, Puerto_Serial
    Tipo_Entrada = int(Puerto_Serial[-1])

    if   Tipo_Entrada == 0: Set_File(STATUS_QR, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
    elif Tipo_Entrada == 1: Set_File(STATUS_QR_S1, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
    elif Tipo_Entrada == 2: Set_File(STATUS_QR_S2, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR




#---------------------------------------------------------------------------------------

def Guardar_QR():
    global QR, Puerto_Serial
    Tipo_Entrada = int(Puerto_Serial[-1])

    #QRG = QR.replace ("<","")
    #QRG = QRG.replace (">","")

    if Tipo_Entrada == 0:
        Clear_File(COM_QR)          # Borrar QR
        Set_File(COM_QR, QR)       # Guardar QR
    elif Tipo_Entrada == 1:
        Clear_File(COM_QR_S1)          # Borrar QR
        Set_File(COM_QR_S1, QR)       # Guardar QR
    elif Tipo_Entrada == 2:
        Clear_File(COM_QR_S2)          # Borrar QR
        Set_File(COM_QR_S2, QR)       # Guardar QR





#---------------------------------------------------------------------------------------

def Activar_Tag():
    global Puerto_Serial
    Tipo_Entrada = int(Puerto_Serial[-1])

    if   Tipo_Entrada == 0: Set_File(STATUS_NFC, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
    elif Tipo_Entrada == 1: Set_File(STATUS_NFC_S1, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
    elif Tipo_Entrada == 2: Set_File(STATUS_NFC_S2, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR


#---------------------------------------------------------------------------------------

def Guardar_Tag(Tag):
    global Puerto_Serial
    Tipo_Entrada = int(Puerto_Serial[-1])
    #global QR
    TagG = Tag.replace ("<","")
    TagG = TagG.replace (">","")
    TagG = TagG.replace ("TN:","")
    TagG = TagG.replace ("TR:","")

    #Set_File(COM_RELE,'Access granted-E')
    if Tipo_Entrada == 0:
        Clear_File(COM_NFC)          # Borrar QR
        Set_File(COM_NFC, TagG)       # Guardar QR
    elif Tipo_Entrada == 1:
        Clear_File(COM_NFC_S1)          # Borrar QR
        Set_File(COM_NFC_S1, TagG)       # Guardar QR
    elif Tipo_Entrada == 2:
        Clear_File(COM_NFC_S2)          # Borrar QR
        Set_File(COM_NFC_S2, TagG)       # Guardar QR


    #Clear_File(COM_NFC)          # Borrar QR
    #Set_File(COM_NFC, TagG)       # Guardar QR


    #Clear_File(COM_TECLADO)          # Borrar QR
    #Set_File(COM_TECLADO, '6.' + TagG)       # Guardar QR


#---------------------------------------------------------------------------------------

def Guardar_Teclado(Teclado):
    global Puerto_Serial
    Tipo_Entrada = int(Puerto_Serial[-1])

    TecladoG = Teclado.replace ("<","")
    TecladoG = TecladoG.replace (">","")
    TecladoG = TecladoG.replace ("TC:","")

    if Tipo_Entrada == 0:
        Clear_File(COM_TECLADO)          # Borrar QR
        Set_File(COM_TECLADO, TecladoG)       # Guardar QR
    elif Tipo_Entrada == 1:
        Clear_File(COM_TECLADO_S1)          # Borrar QR
        Set_File(COM_TECLADO_S1, TecladoG)       # Guardar QR
    elif Tipo_Entrada == 2:
        Clear_File(COM_TECLADO_S2)          # Borrar QR
        Set_File(COM_TECLADO_S2, TecladoG)       # Guardar QR


#---------------------------------------------------------------------------------------

def Activar_Teclado():
    global Puerto_Serial
    Tipo_Entrada = int(Puerto_Serial[-1])

    if   Tipo_Entrada == 0: Set_File(STATUS_TECLADO, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
    elif Tipo_Entrada == 1: Set_File(STATUS_TECLADO_S1, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
    elif Tipo_Entrada == 2: Set_File(STATUS_TECLADO_S2, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR

    #Set_File(STATUS_TECLADO, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
