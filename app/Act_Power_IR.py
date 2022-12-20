#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Libreria personal para el control del led de potencia con un IR.



# ideas a implementar
# Activar/desactivar el proceso con un archivo
para configuracion de diferentes tipos de dispositivos




"""
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------

import commands
import sys
import time
import RPi.GPIO as GPIO #Libreria Python GPIO
import threading

#-----------------------------------------------------------
#                       CONTANTES
#-----------------------------------------------------------

GPIO.setmode (GPIO.BOARD)
CC_Pin_IR =  31                     # pin de intrada ir
CC_Pin_Led  =  3                    # pin led potencia
GPIO.setup(CC_Pin_IR, GPIO.IN)
GPIO.setup(CC_Pin_Led, GPIO.OUT)

Estados_IR = '1'                    #
Estados_Antes_IR = '1'              #

#-----------------------------------------------------------
#----                   Funciones                       ----
#-----------------------------------------------------------

def Eventos_IR():
    global Estados_IR
    global Estados_Antes_IR
    global CC_Pin_IR
    global CC_Pin_Led

    Estados_IR= str(GPIO.input(CC_Pin_IR))

    if Estados_IR != Estados_Antes_IR:
        Estados_Antes_IR =  Estados_IR

        if Estados_IR == '0':
            GPIO.output(CC_Pin_Led, GPIO.LOW)
            #time.sleep(0.10)
            #GPIO.output(CC_Pin_Led, GPIO.HIGH)
        else:
            GPIO.output(CC_Pin_Led, GPIO.HIGH)

def Ciclo ():
    while (True):
            time.sleep(0.1)
            Eventos_IR()

#-----------------------------------------------------------
#                   Configuracion default
#-----------------------------------------------------------

GPIO.output(CC_Pin_Led, GPIO.LOW)
time.sleep(1.10)
GPIO.output(CC_Pin_Led, GPIO.HIGH)

#-----------------------------------------------------------
#               Pruebas de funcioanmiento
#-----------------------------------------------------------

Ciclo ()
