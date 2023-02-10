#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor:  Luding Castaneda,
        Anderson Amaya Pulido

Libreria personal para procesar un qr.




# ideas a implementar




# dmesg | grep tty
"""
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
import time
from threading import Thread

#---------------------------------
#           Librerias personales
#---------------------------------
from lib.Lib_settings import *  # importar con los mismos nombres

#-----------------------------------------------------------
#                       CONTANTES
#-----------------------------------------------------------

MR_Mensajes = 0     # 0: NO print  1: Print
Config_Mod  = Get_Mod_Respuesta()
Tiempo_stop = float(Config_Mod['Time_Sleep_Mod'])
#---------------------------------------------------------
#---------------------------------------------------------
#----       Clase respuestas para lso diferentes dispsotyivos cae cat hub
#---------------------------------------------------------
#---------------------------------------------------------

class SALIDAS_ACCIONES(object):

    #---------------------------------------------------------
    def __init__(self, Locacion, lectora, rele):

        self.Canal_lectora  = lectora
        self.Canal_rele  = rele
        self.Sede   = Locacion
        #---------------------------------------
        self.COM_Respuesta     = ''
        self.Salida_COM_RELE    = ''
        self.Salida_COM_LED     = ''
        self.Salida_COM_BUZZER  = ''

        #---------------------------------------
        self.Enrutar_Archivos_Salidas()
        #print self.Salida_COM_RES
    #---------------------------------------------------------
    def Ciclo_revicion(self):
        global Tiempo_stop
        while (True):
            time.sleep(Tiempo_stop)                # 0.05
            Comando = Get_File(self.COM_Respuesta)
            if Comando != '':
                self.Acciones_Dispositivo(Comando)
                Clear_File(self.COM_Respuesta)
    #---------------------------------------------------------
    def Enrutar_Archivos_Salidas(self):

        if    self.Canal_lectora == '3':
            self.COM_Respuesta      = os.path.join(COM_RES)
            self.Salida_COM_RES     = COM_RES
            self.Salida_COM_RELE    = COM_RELE_S0
            self.Salida_COM_LED     = COM_LED
            self.Salida_COM_BUZZER  = COM_BUZZER
        elif  self.Canal_lectora == '0': self.COM_Respuesta = os.path.join(COM_RES)
        elif  self.Canal_lectora == '1': self.COM_Respuesta = os.path.join(COM_RES_S1)
        elif  self.Canal_lectora == '2': self.COM_Respuesta = os.path.join(COM_RES_S2)
        #--------------------------------------------------------------------
        if    self.Canal_rele == '0':   self.Salida_COM_RELE = os.path.join(COM_RELE_S0)
        elif  self.Canal_rele == '1':   self.Salida_COM_RELE = os.path.join(COM_RELE_S1)
        elif  self.Canal_rele == '2':   self.Salida_COM_RELE = os.path.join(COM_RELE_S2)
        if MR_Mensajes :
            print 'Sede :', self.Sede
            print 'Ruta Respuesta :', self.COM_Respuesta
            print 'Ruta Rele :', self.Salida_COM_RELE

        """
        if self.Sede == 'S0':

            if  self.Canal == '3':

            elif  self.Canal == '0':    self.Salida_COM_RES     = S0 + COM_RES
            elif  self.Canal == '1':    self.Salida_COM_RES     = S1 + COM_RES_S1
            elif  self.Canal == '2':    self.Salida_COM_RES     = S2 + COM_RES_S2

        elif self.Sede == 'S1':

            if  self.Canal == '0':    self.Salida_COM_RES       = S0 + COM_RES
            elif  self.Canal == '1':    self.Salida_COM_RES     = S1 + COM_RES_S1
            elif  self.Canal == '2':    self.Salida_COM_RES     = S2 + COM_RES_S2

        elif self.Sede == 'S2':

            if  self.Canal == '0'  :    self.Salida_COM_RES     = S0 + COM_RES
            elif  self.Canal == '1':    self.Salida_COM_RES     = S1 + COM_RES_S1
            elif  self.Canal == '2':     self.Salida_COM_RES    = S2 + COM_RES_S2
        if MR_Mensajes : print self.Salida_COM_RES
        """

    #---------------------------------------------------------
    def Access_Entry_Users(self):

        Set_File(self.Salida_COM_RELE,'Access granted-E')
        if  self.Canal_lectora == 'S3':
            Set_File(self.Salida_COM_LED,'Access granted-E')
            Set_File(self.Salida_COM_BUZZER , '1')           # activar sonido por 500*1
    #---------------------------------------------------------
    def Access_Out_Users(self):

        Set_File(self.Salida_COM_RELE,'Access granted-S')
        if  self.Canal_lectora == 'S3':
            Set_File(self.Salida_COM_LED,'Access granted-S')
            Set_File(self.Salida_COM_BUZZER , '1')           # activar sonido por 500*1
    #---------------------------------------------------------
    def Access_Denied_Users(self):
        Set_File(self.Salida_COM_RELE,'Error')
        if  self.Canal_lectora == 'S3':
            Set_File(self.Salida_COM_LED,'Error')
            Set_File(self.Salida_COM_BUZZER, '1')           # activar sonido por 500*1
    #---------------------------------------------------------
    def Acciones_Dispositivo(self, Comando):
        #--------- para usuarios
        if    'Access granted-E' in Comando :  self.Access_Entry_Users()
        elif  'Access granted-S' in Comando :  self.Access_Out_Users()
        elif  'Denied'           in Comando :  self.Access_Denied_Users()
        else:                                  self.Access_Denied_Users()
    #---------------------------------------------------------
    def Inicio_Revicion(self):
        self.th_swrite = Thread(target=self.Ciclo_revicion)
        self.th_swrite.start()


#-----------------------------------------
#           Configuraciones de Salidas
#-----------------------------------------
VECTOR_SALIDAS = []

data_Reles    = Get_Salidas()
data_Lectoras = Get_Lectoras()
VECTOR_Mapin = []

#-----------------------------------------
#           funcion de mapeo
#-----------------------------------------
for Lectora in data_Lectoras: #prioridad locaciones --
    Canal_lectora = Lectora['Puerto']
    Locacion_Lectora = Lectora['Locacion']
    for Rele in data_Reles: #prioridad locaciones --
        Canal_rele= Rele['Puerto']
        if Locacion_Lectora == Rele['Locacion']:
            #print 'posible ruta salida:'
            VECTOR_Mapin.append([Locacion_Lectora,Canal_lectora, Canal_rele])
#-----------------------------------------
for Mapa in VECTOR_Mapin:
    #print Mapa
    try:
        if MR_Mensajes : print 'Mapa :',Mapa[0],Mapa[1],Mapa[2]
        VECTOR_SALIDAS.append(SALIDAS_ACCIONES ( Mapa[0], Mapa[1], Mapa[2] ))
    except:
        if MR_Mensajes : print 'Key Error no definidas'



for Salida_Rele in VECTOR_SALIDAS:
    Salida_Rele.Inicio_Revicion()
