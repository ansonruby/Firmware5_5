#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Libreria personal para el control del Buzzer.



# ideas a implementar






"""
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------

#-------------------------------------------------------
#----      importar complementos                    ----
#-------------------------------------------------------
import os
import time

import RPi.GPIO as GPIO #Libreria Python GPIO

#---------------------------------
#           Librerias personales
#---------------------------------

from lib.Lib_File import *  # importar con los mismos nombres
from lib.Lib_Rout import *  # importar con los mismos nombres

#-----------------------------------------------------------
#                       CONSTANTES
#-----------------------------------------------------------
Pin_Buzzer      = 7                   # Pin de salida de Buzzer
Tiempo_sonido   = 0.05                # Tiempo minimo de activacion

#-----------------------------------------------------------
#                       DEFINICIONES
#-----------------------------------------------------------

#-----------------------------------------------------------
#                       VARIABLES
#-----------------------------------------------------------

#-----------------------------------------------------------
#----      Funciones para el manejo del buzzer     ----
#-----------------------------------------------------------

def sonido(Rango):                                           # Funcion para Activar sonido

    global CC_Pin
    GPIO.output(Pin_Buzzer, GPIO.HIGH)
    time.sleep(Rango)
    GPIO.output(Pin_Buzzer, GPIO.LOW)

#-----------------------------------------------------------
def Control_Sonidos_Por_Archivo():                          # Seleccion de sonido

    global Tiempo_sonido
    Dato = Get_File(COM_BUZZER)
    if len(Dato) >= 1 :
        Clear_File(COM_BUZZER)
        if      (Dato =='0'): sonido(Tiempo_sonido*1)
        elif    (Dato =='1'): sonido(Tiempo_sonido*2)
        elif    (Dato =='2'): sonido(Tiempo_sonido*3)
        elif    (Dato =='3'): sonido(Tiempo_sonido*4)
        elif    (Dato =='4'): sonido(Tiempo_sonido*5)

#-----------------------------------------------------------
def Ciclo_Buzzer():
    while (True):
        time.sleep(0.1)                # 0.05
        Control_Sonidos_Por_Archivo()

#-----------------------------------------------------------
#                   Configuracion local
#-----------------------------------------------------------

GPIO.setmode (GPIO.BOARD)
GPIO.setup(Pin_Buzzer, GPIO.OUT)
#-----------------------------------------------------------
#               Pruebas de funcionamiento
#-----------------------------------------------------------

#sonido(0.05*5)
Ciclo_Buzzer()

#-----------------------------------------------------------
#-----------------------------------------------------------
#                       RESUMEN y descripciones
#-----------------------------------------------------------
#-----------------------------------------------------------
# sonido(Rango):
# Control_Sonidos_Por_Archivo():
