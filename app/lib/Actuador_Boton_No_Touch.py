#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Libreria personal para el control del Buzzer.



# ideas a implementar.






"""
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------

#---------------------------------------------------------------------------------------
#                                   importar complementos
#---------------------------------------------------------------------------------------

import commands
import sys
import time
import RPi.GPIO as GPIO #Libreria Python GPIO
import threading

#---------------------------------------------------------------------------------------
#                                   Librerias personale
#---------------------------------------------------------------------------------------

from Lib_File import *                              # importar con los mismos nombres
from Lib_Rout import *                              # importar con los mismos nombres


"""
import lib.Control_Torniquete
import lib.Control_Archivos


Entrar                  = lib.Control_Torniquete.Entrar
Salir                   = lib.Control_Torniquete.Salir

Leer_Estado             = lib.Control_Archivos.Leer_Estado
Escrivir_Estados        = lib.Control_Archivos.Escrivir_Estados
Escrivir_Archivo        = lib.Control_Archivos.Escrivir_Archivo
Verificar_aforo         = lib.Control_Archivos.Verificar_aforo

"""

#---------------------------------------------------------------------------------------
#                       CONSTANTES
#---------------------------------------------------------------------------------------

Pin_No_Touch        = 36                           # pin boton no touch

#---------------------------------------------------------------------------------------
#                                   VARIABLES
#---------------------------------------------------------------------------------------

Status_Hilo_activo  = 0                            # Estado del hilo
Filtro              = [0, 0, 0, 0]                 # filtro



#---------------------------------------------------------------------------------------
#                                   Funciones para el boton no touch
#---------------------------------------------------------------------------------------

#--- leer el boton no touch

def Get_Switch():
    global Filtro

    Filtro[3] = Filtro[2]
    Filtro[2] = Filtro[1]
    Filtro[1] = Filtro[0]
    Filtro[0] = int(GPIO.input(Pin_No_Touch))

    fil =float(Filtro[3]+ Filtro[2] + Filtro[1]+ Filtro[0])/4
    if fil >= 0.25 :    return '1'  # print '1'
    else:               return '0'  # print '0'

    #b= str(GPIO.input(Pin_No_Touch))
    #return b

#--- Activar hilo boton no touch

def Activar_Hilos_Boton():
    global Boton_Activo
    global Status_Hilo_activo

    if Boton_Activo.isAlive() is False:
        Status_Hilo_activo = 1
        Boton_Activo = threading.Thread(target=Proceso_Salir_Por_Boton)#, args=(0,))
        Boton_Activo.start()

        #print 'Activado'

#--- Proceso salir por boton

def Proceso_Salir_Por_Boton():
    global Status_Hilo_activo

    tiempo_actual = str(int(time.time()*1000.0))
    dato = '.' + tiempo_actual + '.4.1.1'
    #print dato
    # para registros de salidas
    Add_File(TAB_AUTO_TIPO_3, dato + '\n')

    Set_File(COM_LED , 'Access granted-S')
    Set_File(COM_RELE, 'Access granted-S')

    Tiempo_Rele =int(Get_File(CONF_TIEM_RELE))
    time.sleep(Tiempo_Rele)

    #esperar que lo suelten
    while 1:
        time.sleep(0.05)
        if Get_Switch() == '0':
            #print 'stop'
            break
    Status_Hilo_activo = 0

#--- Evento del boton

def Eventos_Boton_Salida():
    global Status_Hilo_activo
    #print Get_Switch()
    if Get_Switch() == '1' and Status_Hilo_activo == 0:
        Activar_Hilos_Boton()







#---------------------------------------------------------------------------------------
#                                   Configuracion local
#---------------------------------------------------------------------------------------

GPIO.setmode (GPIO.BOARD)
GPIO.setup(Pin_No_Touch, GPIO.IN)

Boton_Activo   = threading.Thread(target=Proceso_Salir_Por_Boton)


print 'hola'
while (True):

        time.sleep(0.05)
        Eventos_Boton_Salida()


"""
# pendiente de reubicacion si es nesesario para llevar el aforo
def Verificar_aforo():
    global	N_A_Lector
    Contador=0
    salidas =0
    usuarios =0
    archivo = open(N_A_Lector, 'r')
    archivo.seek(0)
    for linea in archivo.readlines():
        s=linea.rstrip('\n')
        s=s.rstrip('\r')
        s2 =s.split(".")
        #ID2 = s2[1] + '.'+ s2[2]  + '.'+ s2[3]
        #print 'ID: '+ s
        divi = len(s2)
        if divi >=3:
            if s2[divi-3] == '4' :  salidas = salidas + 1
            else                 :  usuarios =usuarios + 1
    archivo.close()
    #print salidas
    #print usuarios
    return usuarios - salidas


"""
