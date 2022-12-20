#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Libreria personal para el control de multiples dispositivos por rs485




# ideas a implementar





"""
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
#---------------------------------
#           Librerias personales
#---------------------------------

from Lib_File import *            # importar con los mismos nombres
from Lib_Rout import *            # importar con los mismos nombres



#-------------------------------------------------------
# inicio de variable	--------------------------------------

FM_Mensajes = 1     # 0: NO print  1: Print

TIEMPO_MODBUS_ESPERA = 500 # 500 milisegundo de espera para la respuesta


#-------------------------------------------------------
#           definiciones tramas Modbus
#-------------------------------------------------------

#------   definicion de inicio y final y separadores -----

TRAMA_INIT                      = "!"
TRAMA_FIN                       = "?"
CUARTETA_DEFAULT                = "0000"
TRAMA_SEPARADOR                 = ":"

#------   Default IDs-----

ID_ALL                          = "0000"        #  para todos brokast
ID_MASTER_DEFAULT               = "0001"        #  ID_maestro Default

FUN_GET_ID                      = "0000"        #Devolver ID si esta el dispositivo
FUN_CAMBIO_ID                   = "0001"        #Cambio de ID
FUN_TIPO_MODULO                 = "0002"        #Get Tipo de Modulo (Usuario , rele)

FUN_MODULO_RELE                 = "0004"        #Comado para encender los modulos de relevos

FUN_RESPUESTAS                  = "3000"        #respuesta de dispotivos
FUN_RESPUESTAS_OK               = "3001"        #respuesta de dispotivo OK o realizado

FUN_DATA_M_USUARIO              = "4001"        #Verificacion Rapida de datos
FUN_SET_COM_M_USUARIO           = "4002"        #Embiar comando Modulo sauro


#---------- Adicionales para comados 4002 para modulo usuario

VERDE_ENTRADA                   = "0001"        #duracion constantes
VERDE_SALIDA                    = "0002"        #duracion constantes
ROJO_DENEGADO                   = "0003"        #duracion constantes



FUN_                            = "0000"        #stado del disposivo


#-------------------------------------------------------
#           Ejemplos tramas Modulos relevos
#-------------------------------------------------------
"""
Estructura basica de tramas TX del maestro

  Inicio   ID_Dispositivo   Funciones           DATA                  fin trama
"   !           0000          0000              0000                     ?       "

Estructura basica de tramas RX del maestro

  Inicio   ID_Dispositivo   Funciones           Cantidad     Separador         DATA       fin trama

"   !           0000          0000               0010             :          0123456789       ?       "


Ejemplos

1. Ping a un dispositivos

TX_Maestro:     !0002 0000 0000?      # Al dispositivos 0002 devolver ID
RX_Modulo:      !0001 3000 0002?      # Respuesta del modulo con su ID con TIEMPO_MODBUS_ESPERA

2. Cambio de ID de un dispotivos

TX_Maestro:     !0002 0001 0003?      # Al dispositivos 0002 cambiar al ID 0003
RX_Modulo:      !0001 3000 0003?      # Respuesta del modulo con su ID con TIEMPO_MODBUS_ESPERA

3. Get tipo Modulo

TX_Maestro:     !0002 0002 0000?      # Al dispositivos 0002 se le pide que tipo de modulo es
RX_Modulo:      !0001 3000 0001?      # Respuesta del modulo con tipos 0001:Relevos 0002: Usuarios con TIEMPO_MODBUS_ESPERA


4. Pedir datos a Modulo usuarios

TX_Maestro:     !0002 4001 0000?      # Al dispositivos 0002 se le pide datos del usuario digitados (QR,NFC,Tecaldo)
RX_Modulo:      !0001 3000 0000?      # Respuesta del modulo No hay datos con TIEMPO_MODBUS_ESPERA

RX_Modulo:      !0001 3000 0026 : <123123.23423sadsdgfweerw> ?      # Respuesta del modulo con un QR        con TIEMPO_MODBUS_ESPERA
RX_Modulo:      !0001 3000 0017 : <TN:4545awdsgfad> ?               # Respuesta del modulo con un TaG       con TIEMPO_MODBUS_ESPERA
RX_Modulo:      !0001 3000 0011 : <TC:123123> ?                     # Respuesta del modulo con un Teclado   con TIEMPO_MODBUS_ESPERA

5. Comado a Modulo usuarios

TX_Maestro:     !0002 4002 0001?      # VERDE_ENTRADA
RX_Modulo:      !0001 3001 0000?      # OK procesado con TIEMPO_MODBUS_ESPERA

TX_Maestro:     !0002 4002 0002?      # VERDE_SALIDA
RX_Modulo:      !0001 3001 0000?      # OK procesado con TIEMPO_MODBUS_ESPERA

TX_Maestro:     !0002 4002 0003?      # ROJO_DENEGADO
RX_Modulo:      !0001 3001 0000?      # OK procesado con TIEMPO_MODBUS_ESPERA


5. Comado a Modulo relevos


TX_Maestro:     !1234 0004 0001?      # activar rele iz por 1 seg, con ID 1234
RX_Modulo:      !0001 3001 0000?      # OK procesado con TIEMPO_MODBUS_ESPERA

TX_Maestro:     !1234 0004 0101?      # activar rele derecho por 1 seg, con ID 1234
RX_Modulo:      !0001 3001 0000?      # OK procesado con TIEMPO_MODBUS_ESPERA

TX_Maestro:     !1234 0004 0102?      # activar rele derecho por 2 seg, con ID 1234
RX_Modulo:      !0001 3001 0000?      # OK procesado con TIEMPO_MODBUS_ESPERA

TX_Maestro:     !1234 0004 0300?      # Cerra relevos, con ID 1234
RX_Modulo:      !0001 3001 0000?      # OK procesado con TIEMPO_MODBUS_ESPERA








#//---------------------  funciones que son esclusivas del modulo

!xxxx00020000?    // !123400020000? le responde al maaestro con su id,  funcion 2 y dato 0
!xxxx00030000?    // !123400030000? le responde al maaestro OK
!xxxx00040001?    // !1234 0004 0001? activar rele iz por 1 seg, requiere el ID del moodulo xxxx






#//---------------------  funciones que son para todos ojo si tienen todo el mismo ID responde al mismo tiempo




#  xxxx : ID del modulo al cual se quiere comunicar

#//---------------------  funciones que son para todos ojo si tienen todo el mismo ID responde al mismo tiempo

!xxxx0000XXXX?    //devuelve el  id de los modulos  por la misma linea    // mejorar para enviar datos por rs485
!xxxx0001XXXX?    //cambiar el ID del Modulo por lo que se coloque en las XXXX

#//---------------------  funciones que son esclusivas del modulo

!xxxx00020000?    // !123400020000? le responde al maaestro con su id,  funcion 2 y dato 0
!xxxx00030000?    // !123400030000? le responde al maaestro OK
!xxxx00040001?    // !123400040001? activar rele iz por 1 seg, requiere el ID del moodulo xxxx


"""

#-------------------------------------------------------
#           Ejemplos tramas Modulos Usuarios
#-------------------------------------------------------
"""
#  xxxx : ID del modulo al cual se quiere comunicar


#//---------------------  funciones que son esclusivas del modulo Usuarios

!xxxx00020000?    // !123400020000? le responde al maaestro con su id,  funcion 2 y dato 0
!xxxx00030000?    // !123400030000? le responde al maaestro OK   comos su fuero un ping
!xxxx10020000?    // !123410020000? pericion de dato para procesar respuesta el !dato? o !NO?


#//---------------------  funciones que son para todos ojo si tienen todo el mismo ID responde al mismo tiempo

!xxxx0000XXXX?    //devuelve el  id de los modulos  por la misma linea    // mejorar para enviar datos por rs485
!xxxx0001XXXX?    //cambiar el ID del Modulo por lo que se coloque en las XXXX


"""


"""
RX_MODBUS                 = FIRM + COMMA + 'Serial_Modbus/RX_Modbus.txt'                        # Datos leidos del Nfc
TX_MODBUS                 = FIRM + COMMA + 'Serial_Modbus/TX_Modbus.txt'                        # Datos leidos del Nfc
PILA_MODBUS               = FIRM + COMMA + 'Serial_Modbus/PILA_Modbus.txt'                      # Datos leidos del Nfc

ID_MOD_USUARIOS           = FIRM + COMMA + 'Serial_Modbus/ID_MOD_Usuarios.txt'                      # Datos leidos del Nfc
ID_MOD_RELES               = FIRM + COMMA + 'Serial_Modbus/ID_MOD_Reles.txt'                      # Datos leidos del Nfc

"""



#---------------------------------------------------------------------
#----       funciones de uso comun para peticiones a los dispositivos
#---------------------------------------------------------------------

#---------------------------------------------------------------------
#----       Funciones Genetadores de tramas
#---------------------------------------------------------------------


#---------------------------------------------------
def Get_Trama_Ping_Dispo(ID):
    # !0002 0000 0000?
    Trama = TRAMA_INIT
    Trama += ID
    Trama += FUN_GET_ID
    Trama += CUARTETA_DEFAULT
    Trama += TRAMA_FIN
    return Trama
#---------------------------------------------------
def Get_Trama_SET_ID_Dispo(ID, ID_SET):
    # !0002 0001 0003?
    Trama = TRAMA_INIT
    Trama += ID
    Trama += FUN_CAMBIO_ID
    Trama += ID_SET
    Trama += TRAMA_FIN
    return Trama
#---------------------------------------------------
def Get_Trama_Tipo_Dispo(ID):
    # !0002 0002 0000?
    Trama = TRAMA_INIT
    Trama += ID
    Trama += FUN_TIPO_MODULO
    Trama += CUARTETA_DEFAULT
    Trama += TRAMA_FIN
    return Trama
#---------------------------------------------------
def Get_Trama_Data_Modulo_Usuario(ID):
    # !0002 4001 0000?
    Trama = TRAMA_INIT
    Trama += ID
    Trama += FUN_DATA_M_USUARIO
    Trama += CUARTETA_DEFAULT
    Trama += TRAMA_FIN
    return Trama
#---------------------------------------------------
def Get_Trama_COMAN_Modulo_Usuario(ID,TIPO):
    # !0002 4002 0001?
    Trama = TRAMA_INIT
    Trama += ID
    Trama += FUN_SET_COM_M_USUARIO

    if TIPO == 'Entrada':       Trama += VERDE_ENTRADA
    if TIPO == 'Salida':        Trama += VERDE_SALIDA
    if TIPO == 'Denegado':      Trama += ROJO_DENEGADO

    Trama += TRAMA_FIN
    return Trama
#---------------------------------------------------


#---------------------------------------------------------------------
#----       Funciones Dispositivos
#---------------------------------------------------------------------

#---------------------------------------------------
def Get_Dispositivos():


    Modbus_N_Dispositivos=0
    Modbus_ID_Dispositivos = []

    MODULOS = Get_File(ID_MOD_USUARIOS)
    Modu_N  = MODULOS.split("\n")
    for Modulo in range(len(Modu_N)):
        #print Modu_N[Modulo]

        if len(Modu_N[Modulo])>= 3:

            Modbus_ID_Dispositivos.append( Modu_N[Modulo])
            Modbus_N_Dispositivos = Modbus_N_Dispositivos + 1
    return Modbus_N_Dispositivos, Modbus_ID_Dispositivos

#---------------------------------------------------



#---------------------------------------------------------------------
#----           Funciones       Resepcion
#---------------------------------------------------------------------

#---------------------------------------------------
def Separacion_trama_Recepcion(Trama):
    #if FM_Mensajes:print Trama
    TaCadena = len (Trama)
    Inicio   = Trama[0:1]
    Fin      = Trama[TaCadena-1:TaCadena]
    ID_Dispo = Trama[1:5]
    Funcion  = Trama[5:9]
    Data     = Trama[9:13]

    if (Inicio == TRAMA_INIT ) and (Fin == TRAMA_FIN):
        if TaCadena>14:
            #print Trama[13:14]
            if Trama[13:14] == ':':
                Data = Trama[14:TaCadena-1]
                #if FM_Mensajes: print 'Datos adicionales:' + Data
                return ID_Dispo,Funcion,Data,1
            else:
                #if FM_Mensajes: print 'No definido'
                return ID_Dispo, Funcion, CUARTETA_DEFAULT,0
        else:
            return ID_Dispo,Funcion,Data,1

        return 1
    else:
        #if FM_Mensajes: print 'No cumple parametros'
        return CUARTETA_DEFAULT, CUARTETA_DEFAULT, CUARTETA_DEFAULT,0
#---------------------------------------------------




"""
if FM_Mensajes: print 'Modbus'

print Separacion_trama_Recepcion('!000130000002?')
print Separacion_trama_Recepcion('!000130000026:<123123.23423sadsdgfweerw>?')
print Separacion_trama_Recepcion('!000130000017:<TN:4545awdsgfad>?')
"""





"""

print Get_Trama_Ping_Dispo('0002')
print Get_Trama_SET_ID_Dispo('0002','0003')
print Get_Trama_Tipo_Dispo('0002')
print Get_Trama_Data_Modulo_Usuario('0002')
print Get_Trama_COMAN_Modulo_Usuario('0002', 'Entrada')
print Get_Trama_COMAN_Modulo_Usuario('0002', 'Salida')
print Get_Trama_COMAN_Modulo_Usuario('0002', 'Denegado')

Get_Dispositivos()

print Modbus_N_Dispositivos
print Modbus_ID_Dispositivos
"""






"""

RX_Modulo:      !0001 3000 0002?      # Respuesta del modulo con su ID con TIEMPO_MODBUS_ESPERA

2. Cambio de ID de un dispotivos

RX_Modulo:      !0001 3000 0003?      # Respuesta del modulo con su ID con TIEMPO_MODBUS_ESPERA

3. Get tipo Modulo

RX_Modulo:      !0001 3000 0001?      # Respuesta del modulo con tipos 0001:Relevos 0002: Usuarios con TIEMPO_MODBUS_ESPERA

4. Pedir datos a Modulo usuarios

RX_Modulo:      !0001 3000 0000?      # Respuesta del modulo No hay datos con TIEMPO_MODBUS_ESPERA
RX_Modulo:      !0001 3000 0026 : <123123.23423sadsdgfweerw> ?      # Respuesta del modulo con un QR        con TIEMPO_MODBUS_ESPERA
RX_Modulo:      !0001 3000 0017 : <TN:4545awdsgfad> ?               # Respuesta del modulo con un TaG       con TIEMPO_MODBUS_ESPERA
RX_Modulo:      !0001 3000 0011 : <TC:123123> ?                     # Respuesta del modulo con un Teclado   con TIEMPO_MODBUS_ESPERA

5. Comado a Modulo usuarios

RX_Modulo:      !0001 3001 0000?      # OK procesado con TIEMPO_MODBUS_ESPERA



"""
