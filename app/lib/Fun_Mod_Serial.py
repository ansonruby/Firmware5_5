#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor:  Luding Castaneda,
        Anderson Amaya Pulido

Libreria personal para procesar un qr.




# ideas a implementar




"""
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------

import commands
import serial
import os, time
from serial import SerialException
from threading import Thread


#---------------------------------
#           Librerias personales
#---------------------------------

from Lib_File import *            # importar con los mismos nombres
from Lib_Rout import *            # importar con los mismos nombres


#-----------------------------------------------------------
#                       CONSTANTES
#-----------------------------------------------------------

FS_Mensajes     = 1               # 0: NO print  1: Print

#-----------------------------------------------------------
#                       Variables
#-----------------------------------------------------------


#---------------------------------------------------------
#---------------------------------------------------------
#----       Clase para multiples lectoras por serial y rs485
#---------------------------------------------------------
#---------------------------------------------------------

class LECTORAS(object):

    #---------------------------------------------------------
    def __init__(self, Port_Config, Lectoras, Locacion):

        self.TAG_NFC =''         # guardado de Tag valido
        self.TAG_NFC_antes =''   # Tag anterior

        self.T_Nuev_TAG   = 0    #
        self.T_Repe_TAG   = 0    #
        self.T_Maximo_TAG = 7    #

        self.QR =''              # guardado de qr valido
        self.QR_antes =''        # QR anterior

        self.T_Maximo_QR = 7     # timepo maximo para verificar un repetido para tipo  3 o tiket
        self.T_Nuev_QR   = 0     # timepo de inicioa de un nuevo qr
        self.T_Repe_QR   = 0     # timepo de inicioa de un nuevo qr

        self.TECLAS =''          # guardado de teclado valido
        self.TECLAS_antes =''    # teclado anterior
        self.Port = -1           #

        self.Canal  = Port_Config
        self.Sede   = Locacion

        #Port_Config = '3'
        if Port_Config == '0':   self.Puerto  = '/dev/ttyUSB0'
        if Port_Config == '1':   self.Puerto  = '/dev/ttyUSB1'
        if Port_Config == '2':   self.Puerto  = '/dev/ttyUSB2'
        if Port_Config == '3':   self.Puerto  = '/dev/ttyS0'

        self.Lectora = Lectoras
        self.Baudios = self.Baut_Serial()

        Arc_Puerto = self.Puerto.split("/")
        Cantidad = 3
        for Intentos in range(Cantidad):
            time.sleep(5)
            #print 'Intento: ' + str(Intentos)
            res = commands.getoutput('dmesg | grep '+ Arc_Puerto[2])
            if len(res) >10:
                try :
                    self.Port = serial.Serial(self.Puerto, baudrate=self.Baudios, timeout=1)
                    print 'OK: ' + self.Puerto
                    break
                except SerialException:
                    print 'Error en el puerto'
                    #print 'Inicio: ' + str(self.Port)
            else: print 'NO exite el puerto'

        #print 'puerto: ' + str(self.Port)
        #---------------------------------------
        self.Lectura_COM_QR     = ''
        self.Lectura_STATUS_QR  = ''
        #---------------------------------------
        self.Enrutar_Archivos_Salida()
    #---------------------------------------------------------
    def Transmitir_Datos(self):
        data = ''
        data = self.Procesar_TX()
        if len(data) >1:    self.Port.write(data)
    #---------------------------------------------------------
    def Recivir_Datos(self):
        rcv = self.Port.read(250)
        if len(rcv) >= 1:  self.Procesar_RX(rcv)
    #---------------------------------------------------------
    def Proceso_Serial(self):
        while True:
            try :

                self.Transmitir_Datos()
                self.Recivir_Datos()

            except SerialException:
                for Intentos in range(3):
                    time.sleep(5)
                    try :
                        self.Port = serial.Serial(self.Puerto, baudrate=self.Baudios, timeout=1)
                        break;
                    except SerialException:
                        print 'error'
    #---------------------------------------------------------
    def Inicio_Lectora(self):
        if self.Port != -1:
            self.th_swrite = Thread(target=self.Proceso_Serial)
            self.th_swrite.start()
    #---------------------------------------------------------

    #---------------------------------------------------------
    #----       funciones del serial
    #---------------------------------------------------------
    #---------------------------------------------------------
    def Procesar_RX(self, Data):
        if      self.Lectora == 'QR600-VHK-E'    : self.Procesar_RX_QR600_VHK_E(Data)
        elif    self.Lectora == 'YHD_M800D_TTL'  : self.Procesar_RX_YHD_M800D_TTL(Data)
        else                                     : print 'NO Resive'
    #---------------------------------------------------------
    def Procesar_TX(self):
        if      self.Lectora == 'QR600-VHK-E'    : return self.TX_QR600_VHK_E()
        elif    self.Lectora == 'YHD_M800D_TTL'  : return ''
        else                              : return ''
    #---------------------------------------------------------
    def Baut_Serial(self):

        if      self.Lectora == 'QR600-VHK-E'    : return self.Baudios_QR600_VHK_E()
        elif    self.Lectora == 'YHD_M800D_TTL'  : return self.Baudios_YHD_M800D_TTL()
        elif    self.Lectora == 'QR600'          : return ''
        else                              : return ''
    #---------------------------------------------------------

    #---------------------------------------------------------
    #----       Funciones para el QR600-VHK-E
    #---------------------------------------------------------
    def Baudios_QR600_VHK_E (self):
            #Baudios , ---
        return 115200
    #---------------------------------------------------------
    def Trama_TX_QR600_VHK_E(self,Tipo):

        Trama = "\xaa\x01\x97\x01\x00\x07\x01\xb6" #default
        if Tipo == 'Peticion':  Trama = "\xaa\x01\x97\x01\x00\x07\x01\xb6"
        elif Tipo == 'Verde':   Trama = "\xaa\x01\x98\x01\x00\x00\x43\x60"
        elif Tipo == 'Rojo':    Trama = "\xaa\x01\x98\x01\x00\xfe\xc2\xe0"

        return Trama
    #---------------------------------------------------------
    def TX_QR600_VHK_E (self):
        data = self.Trama_TX_QR600_VHK_E('Peticion')
        return data
    #---------------------------------------------------------
    def Procesar_RX_QR600_VHK_E(self,rcv):
        global FS_Mensajes
        Estado = 0
        Dato =''
        try :
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
                    secuencia = rcv.split("AA")
                    #print len(secuencia)
                    if len(secuencia) >=3:
                        #print secuencia[1]
                        Estado = 4
                        Dato ="AA"+secuencia[1]+"AA"
                    else:
                        Dato_Hex = self.Convertir_Datos_Hex(rcv)
                        if FS_Mensajes: print 'Datos RX_HEX:' + Dato_Hex
                        Estado, Dato = self.Analisis_Trama_RX__QR600_VHK_E(Dato_Hex)
                    #print Estado


                if Estado != 0 and Estado != 1:
                        if FS_Mensajes: print 'Resultado: ' + str(Estado) + ', ' + str (Dato)
                        if      Estado == 2:    self.Decision_Tag( str(Dato) )
                        elif    Estado == 3:    self.Decision_Teclado(Dato)
                        elif    Estado == 4:    self.Decision_Qr(Dato)
        except:
            print 'Key Error no definidas'

    #---------------------------------------------------------
    def Analisis_Trama_RX__QR600_VHK_E(self,Tag_data):
        try :
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
                        #print Datos[7]
                        if Datos[7] != "1c": Tipo = int(Datos[7])
                        else : return 0, "" #trama ireconosible o sim parametros

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
        except:
            print 'Key Error no definidas'
            return 0, ""

        return 0, ""

    #---------------------------------------------------------
    #----       Funciones para el YHD_M800D_TTL
    #---------------------------------------------------------
    def Baudios_YHD_M800D_TTL (self):
            #Baudios , ---
        return 9600
    #---------------------------------------------------------
    def Procesar_RX_YHD_M800D_TTL(self,rcv):

        global FS_Mensajes

        Estado = 0
        Dato =''

        #if FS_Mensajes: print 'Resicion _Datos TX_QR600_VHK_E'

        if len(rcv) > 0:
            #print 'QR: ' + rcv
            if (rcv.find('<') != -1 ) and (rcv.find('>') != -1) :
                #print rcv.find('<')
                #print rcv.find('>')
                ES_QR = rcv[rcv.find('<'): rcv.find('>')+1]
                #print 'QR: ' + ES_QR
                Estado = 4
                Dato =ES_QR

            else:

                secuencia = rcv.split("AA")
                #print len(secuencia)
                if len(secuencia) >=3:
                    #print secuencia[1]
                    Estado = 4
                    Dato ="AA"+secuencia[1]+"AA"
                else:
                    Dato_Hex = self.Convertir_Datos_Hex(rcv)
                    if FS_Mensajes: print 'Datos RX_HEX:' + Dato_Hex
                    Estado, Dato = self.Analisis_Trama_RX_YHD_M800D_TTL(Dato_Hex)


            if Estado != 0 and Estado != 1:
                    if FS_Mensajes: print 'Resultado: ' + str(Estado) + ', ' + str (Dato)
                    if      Estado == 2:    self.Decision_Tag( str(Dato) )
                    elif    Estado == 3:    self.Decision_Teclado(Dato)
                    elif    Estado == 4:    self.Decision_Qr(Dato)
    #---------------------------------------------------------
    def Analisis_Trama_RX_YHD_M800D_TTL(self,Tag_data):
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
    #----       Funciones para todos los dispositivos
    #---------------------------------------------------------

    def Enrutar_Archivos_Salida(self):
        #print  self.Sede, self.Canal

        if    self.Canal == '0':
            self.Lectura_COM_QR      = COM_QR   # os.path.join(FIRM,HUB,COM_QR)
            self.Lectura_STATUS_QR   = STATUS_QR # os.path.join(FIRM,HUB,STATUS_QR)
        elif  self.Canal == '1':
            self.Lectura_COM_QR      = COM_QR_S1   #os.path.join(FIRM,HUB,COM_QR_S1)
            self.Lectura_STATUS_QR   = STATUS_QR_S1 #os.path.join(FIRM,HUB,STATUS_QR_S1)
        elif  self.Canal == '2':
            self.Lectura_COM_QR      = COM_QR_S2   #os.path.join(FIRM,HUB,COM_QR_S2)
            self.Lectura_STATUS_QR   = STATUS_QR_S2 #os.path.join(FIRM,HUB,STATUS_QR_S2)

        if FS_Mensajes  :
            print self.Sede,": " , self.Lectura_COM_QR
            print self.Sede,": " , self.Lectura_STATUS_QR

        """
        if self.Sede == 'S0':
            if  self.Canal == '0' or self.Canal == '3':
                self.Lectura_COM_QR     = S0 + COM_QR
                self.Lectura_STATUS_QR  = S0 + STATUS_QR
            elif  self.Canal == '1':
                self.Lectura_COM_QR     = S0 + COM_QR_S1
                self.Lectura_STATUS_QR  = S0 + STATUS_QR_S1
            elif  self.Canal == '2':
                self.Lectura_COM_QR     = S0 + COM_QR_S2
                self.Lectura_STATUS_QR  = S0 + STATUS_QR_S2
        elif self.Sede == 'S1':
            if    self.Canal == '0' or self.Canal == '3':
                self.Lectura_COM_QR     = S1 + COM_QR
                self.Lectura_STATUS_QR  = S1 + STATUS_QR
            elif  self.Canal == '1':
                self.Lectura_COM_QR     = S1 + COM_QR_S1
                self.Lectura_STATUS_QR  = S1 + STATUS_QR
            elif  self.Canal == '2':
                self.Lectura_COM_QR     = S1 + COM_QR_S2
                self.Lectura_STATUS_QR  = S1 + STATUS_QR
        elif self.Sede == 'S2':
            if    self.Canal == '0' or self.Canal == '3':
                self.Lectura_COM_QR     = S2 + COM_QR
                self.Lectura_STATUS_QR  = S2 + STATUS_QR
            elif  self.Canal == '1':
                self.Lectura_COM_QR     = S2 + COM_QR_S1
                self.Lectura_STATUS_QR  = S2 + STATUS_QR
            elif  self.Canal == '2':
                self.Lectura_COM_QR     = S2 + COM_QR_S2
                self.Lectura_STATUS_QR  = S2 + STATUS_QR
        """
    #---------------------------------------------------------
    def Convertir_Datos_Hex(self,Dato):

        Tag_data =""
        for letra in Dato:
            datohex = hex(ord(letra))
            Tag_data += datohex.replace('0x'," ")

        return Tag_data
    #---------------------------------------------------------



    #---------------------------------------------------------
    #----       Funciones Teclado
    #---------------------------------------------------------
    def Decision_Teclado(self,Teclado):

        #if SQ_Mensajes: print 'TC:'+ Teclado
        if FS_Mensajes: print 'Nuevo: ' + Teclado
        self.Guardar_Teclado(Teclado)
        self.Activar_Teclado()
    #---------------------------------------------------------
    def Guardar_Teclado(self,Teclado):

        TecladoG = Teclado.replace ("<","")
        TecladoG = TecladoG.replace (">","")
        TecladoG = TecladoG.replace ("TC:","")

        if self.Canal == '0':
            Clear_File(COM_TECLADO)             # Borrar TECLADO
            Set_File(COM_TECLADO, TecladoG)     # Guardar TECLADO
        elif self.Canal == '1':
            Clear_File(COM_TECLADO_S1)          # Borrar TECLADO
            Set_File(COM_TECLADO_S1, TecladoG)  # Guardar TECLADO
        elif self.Canal == '2':
            Clear_File(COM_TECLADO_S2)          # Borrar TECLADO
            Set_File(COM_TECLADO_S2, TecladoG)  # Guardar TECLADO
    #---------------------------------------------------------
    def Activar_Teclado(self):
        if   self.Canal == '0': Set_File(STATUS_TECLADO, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
        elif self.Canal == '1': Set_File(STATUS_TECLADO_S1, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
        elif self.Canal == '2': Set_File(STATUS_TECLADO_S2, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
    #---------------------------------------------------------
    #----       Funciones Tag o Targeta
    #---------------------------------------------------------
    def Decision_Tag(self,Tag):

        #global TAG_NFC, TAG_NFC_antes, T_Nuev_TAG, T_Repe_TAG, T_Maximo_TAG


        self.TAG_NFC = Tag
        #print Tag
        if self.TAG_NFC != self.TAG_NFC_antes:
            self.TAG_NFC_antes = self.TAG_NFC
            #print 'uuu'
            if FS_Mensajes: print 'Nuevo: ' + self.TAG_NFC
            self.Guardar_Tag(self.TAG_NFC)
            self.Activar_Tag()
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
            self.T_Repe_TAG = time.time()
            T_transcurido = int(self.T_Repe_TAG-self.T_Nuev_TAG)
            #print 'T_Diferencia: ' + str(T_transcurido)
            if T_transcurido >= self.T_Maximo_TAG :
                self.T_Nuev_TAG = self.T_Repe_TAG = time.time()
                if FS_Mensajes: print 'Nuevo: ' + self.TAG_NFC
                self.Guardar_Tag(self,self.TAG_NFC)
                self.Activar_Tag(self)
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
                #if SQ_Mensajes:
                print 'Repetido'
                #Set_File(STATUS_REPEAT_QR, '2')    # Estado QR repetido
    #---------------------------------------------------------
    def Activar_Tag(self):
        if   self.Canal == '0': Set_File(STATUS_NFC, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
        elif self.Canal == '1': Set_File(STATUS_NFC_S1, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
        elif self.Canal == '2': Set_File(STATUS_NFC_s2, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
    #---------------------------------------------------------
    def Guardar_Tag(self,Tag):

        TagG = Tag.replace ("<","")
        TagG = TagG.replace (">","")
        TagG = TagG.replace ("TN:","")
        TagG = TagG.replace ("TR:","")

        if self.Canal == '0':
            Clear_File(COM_NFC)          # Borrar NFC
            Set_File(COM_NFC, TagG)      # Guardar NFC
        elif self.Canal == '1':
            Clear_File(COM_NFC_S1)          # Borrar NFC
            Set_File(COM_NFC_S1, TagG)      # Guardar NFC
        elif self.Canal == '2':
            Clear_File(COM_NFC_S2)          # Borrar NFC
            Set_File(COM_NFC_S2, TagG)      # Guardar NFC
    #---------------------------------------------------------
    #----       Funciones QR
    #---------------------------------------------------------
    def Decision_Qr(self,x):
        global FS_Mensajes#, QR, QR_antes, T_Nuev_QR, T_Repe_QR, T_Maximo_QR
        #--------- QR repetido
        self.QR = x
        if self.QR != self.QR_antes:
            self.QR_antes = self.QR
            self.T_Nuev_QR = time.time()
            if FS_Mensajes: print 'Nuevo: ' + self.QR
            self.Guardar_QR()
            self.Activar_QR()
        else:
            #print 'Repetido:' + x + ' , Estado Valido: ' + str(Valido)
            self.T_Repe_QR = time.time()
            T_transcurido = int(self.T_Repe_QR-self.T_Nuev_QR)
            #print 'T_Diferencia: ' + str(T_transcurido)
            if T_transcurido >= self.T_Maximo_QR :
                self.T_Nuev_QR = self.T_Repe_QR = time.time()
                if FS_Mensajes: print 'denuevo: ' + self.QR
                self.Nueva_Avilitacion_portiempo_y_Tipo()
            else:
                if FS_Mensajes: print 'Repetido'
                #Set_File(STATUS_REPEAT_QR, '2')    # Estado QR repetido
    #---------------------------------------------------------
    def Activar_QR(self):
        Set_File(self.Lectura_STATUS_QR, '1')    #Escrivir_Estados('1',8) # Cambiar estado del QR
    #---------------------------------------------------------
    def Guardar_QR(self):
        Clear_File(self.Lectura_COM_QR)
        Set_File(self.Lectura_COM_QR, self.QR)


    def Nueva_Avilitacion_portiempo_y_Tipo(self):
        global FS_Mensajes
        self.QR
        if self.QR[2]=='3': self.Activar_QR()

        """
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
        """

#---------------------------------------------------------
#---------------------------------------------------------
#----                FIN    Clase
#---------------------------------------------------------
#---------------------------------------------------------
