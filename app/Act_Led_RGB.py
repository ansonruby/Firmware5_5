#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Libreria personal para el manejo de led RGB por Comandos.




# ideas a implementar
# Activar/desactivar el proceso con un archivo
para configuracion de diferentes tipos de dispositivos



"""
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------

#-------------------------------------------------------
#----      Control de Led RGB -> WS2812B            ----
#-------------------------------------------------------
# Ejecutar con sudo Python 3.5
#-------------------------------------------------------

import digitalio
from board import *
import time, os
import neopixel
import threading

#---------------------------------
#           Librerias personales
#---------------------------------

from lib.Lib_File import *  # importar con los mismos nombres
from lib.Lib_Rout import *  # importar con los mismos nombres

#-----------------------------------------------------------
#                       CONTANTES
#-----------------------------------------------------------

PIXEL_PIN = D21                 # Pin de control
num_pixels = 10                 # Numero de pixels
num_medio = int(num_pixels/2)   # Mitad de pixel
Led_int=120                     # Intensidad luminica
ORDER = neopixel.RGB            # Pixel color channel order
DELAY = 500                     # Tiempo Blink , retardo de visualizacion

pixel = neopixel.NeoPixel(PIXEL_PIN, num_pixels, pixel_order=ORDER)

Comando_Antes = 0               #
Salir_hilo = 0                  #
#-----------------------------------------------------------
#                       DEFINICIONES
#-----------------------------------------------------------

#-----------------------------------------------------------
#                       VARIABLES
#-----------------------------------------------------------

#-----------------------------------------------------------
#----      Funciones para el manejo de los led          ----
#-----------------------------------------------------------
def Color(Nombre,ID):
    global num_medio
    global Led_int

    COLOR = (0, 0, 0)
    mitad=0
    if 'Verde' == Nombre:       COLOR = ( Led_int, 0, 0)
    elif 'Azul' == Nombre:      COLOR = ( 0, 0, Led_int)
    elif 'Negro' == Nombre:     COLOR = ( 0, 0, 0)
    elif 'Rojo' == Nombre:      COLOR = ( 0, Led_int, 0)
    elif 'Amarillo' == Nombre:  COLOR = ( Led_int, Led_int, 0)
    elif 'Blanco' == Nombre:    COLOR = ( Led_int, Led_int, Led_int)
    else :                      COLOR = ( 0, 0, 0)

    if ID == 1: mitad=num_medio
    for j in range(num_medio):
        pixel[j+mitad] = COLOR

def Ejecutar_Comando(CL_Estados):
    if CL_Estados == '0':	#Estado Inicial
            Color('Azul',1)
            Color('Azul',0)
    elif	CL_Estados == '1':	#blink
            Color('Amarillo',1)
            Color('Amarillo',0)
    elif	CL_Estados == '2':	#blink
            Color('Blanco',1)
            Color('Blanco',0)
    elif	CL_Estados == '3':	#Entrar
            Color('Verde',1)
            Color('Negro',0)
    elif	CL_Estados == '4':	#Salir
            Color('Negro',1)
            Color('Verde',0)
    elif	CL_Estados == '5':	#Sin Acceso
            Color('Rojo',1)
            Color('Rojo',0)
    elif	CL_Estados == '6':	#blink
            Color('Rojo',1)
            Color('Rojo',0)
    elif	CL_Estados == '7':	#Usuario digita Rut sin internet
            Color('Amarillo',1)
            Color('Amarillo',0)
    elif	CL_Estados == '8':	#Usuario digita Rut con internet
            Color('Blanco',1)
            Color('Blanco',0)
    else :						#No definido
            Color('Negro',1)
            Color('Negro',0)

def Blink():
    global Comando_Antes
    global Salir_hilo
    global DELAY
    contador = 0
    while (True):
        time.sleep(0.0001)

        contador = contador + 1
        if contador == 1:   # and contador <= 20 :
            Ejecutar_Comando(Comando_Antes)
        if contador == int(DELAY/2):    Ejecutar_Comando('n')
        if contador >= DELAY:           contador =0
        if Salir_hilo == 0:             break;

def Led_Derecha():
    Tiempo_Rele =int(Get_File(CONF_TIEM_RELE))
    #-----  para visusalisaxcion en el teclado  del estado del usuario
    Conf_Flecha =Get_File(CONF_FLECHA_TECLADO)
    if Conf_Flecha == 'Flecha':     Set_File(STATUS_USER, '3')
    else                      :     Set_File(STATUS_USER, 'Permitido')

    Ejecutar_Comando('3')
    time.sleep(Tiempo_Rele)
    Ejecutar_Comando('0')
    #-----  para visusalisaxcion en el teclado  del estado del usuario
    Clear_File(STATUS_USER)

def Led_Izquierda():
    Tiempo_Rele =int(Get_File(CONF_TIEM_RELE))
    #-----  para visusalisaxcion en el teclado  del estado del usuario
    Conf_Flecha =Get_File(CONF_FLECHA_TECLADO)
    if Conf_Flecha == 'Flecha':     Set_File(STATUS_USER, '4')
    else                      :     Set_File(STATUS_USER, 'Permitido')
    Ejecutar_Comando('4')
    time.sleep(Tiempo_Rele)
    Ejecutar_Comando('0')
    #-----  para visusalisaxcion en el teclado  del estado del usuario
    Clear_File(STATUS_USER)

def Led_Error():
    Tiempo_Rele =int(Get_File(CONF_TIEM_RELE))
    rango = 10
    #-----  para visusalisaxcion en el teclado  del estado del usuario
    Conf_Flecha =Get_File(CONF_FLECHA_TECLADO)
    if Conf_Flecha == 'Flecha':     Set_File(STATUS_USER, '6')
    else                      :     Set_File(STATUS_USER, '6')

    for i in range(rango):
        Ejecutar_Comando('6')
        time.sleep(Tiempo_Rele/(2*rango))
        Ejecutar_Comando('9')
        time.sleep(Tiempo_Rele/(2*rango))

    Ejecutar_Comando('0')
    #-----  para visusalisaxcion en el teclado  del estado del usuario
    Clear_File(STATUS_USER)

def Activar_Hilo_Comando():
    global B_Hilo_Comado
    #print ('Activar Hilo')
    if B_Hilo_Comado.isAlive() is False:
        B_Hilo_Comado = threading.Thread(target=Blink)#, args=(0,))
        B_Hilo_Comado.start()

def Eventos_Led():
    global Comando_Antes
    global Salir_hilo
    global B_Hilo_Entrada, B_Hilo_Salir, B_Hilo_Error

    while (True):
        time.sleep(0.1)
        Comando =Get_File(COM_LED)
        if Comando != '':
            if Comando == 'Access granted-E':
                Direc = Get_File(CONF_DIREC_RELE)   #Leer_Archivo(13)  # Direccion_Torniquete
                if Direc == 'D':
                    #Salir()
                    if B_Hilo_Salir.isAlive() is False:
                        B_Hilo_Salir   = threading.Thread(target=Led_Derecha)
                        B_Hilo_Salir.start()
                else :
                    #Entrar()
                    if B_Hilo_Entrada.isAlive() is False:
                        B_Hilo_Entrada   = threading.Thread(target=Led_Izquierda)
                        B_Hilo_Entrada.start()

                Clear_File(COM_LED)

            elif Comando == 'Access granted-S':
                #print ('S')
                Direc = Get_File(CONF_DIREC_RELE)   #Leer_Archivo(13)  # Direccion_Torniquete
                if Direc == 'D':
                    #Entrar()
                    if B_Hilo_Entrada.isAlive() is False:
                        B_Hilo_Entrada   = threading.Thread(target=Led_Izquierda)
                        B_Hilo_Entrada.start()
                else :
                    #Salir()
                    if B_Hilo_Salir.isAlive() is False:
                        B_Hilo_Salir   = threading.Thread(target=Led_Derecha)
                        B_Hilo_Salir.start()

                Clear_File(COM_LED)

            elif Comando == 'Error':

                if B_Hilo_Error.isAlive() is False:
                    B_Hilo_Error   = threading.Thread(target=Led_Error)
                    B_Hilo_Error.start()

                Clear_File(COM_LED)

            elif Comando != Comando_Antes :
                #print (Comando)
                Salir_hilo = 0
                Comando_Antes = Comando
                if Comando == '6' or Comando == '1' or Comando == '2':
                    Salir_hilo = 1
                    Activar_Hilo_Comando()
                else :
                    Ejecutar_Comando(Comando)
                Clear_File(COM_LED)


#-------------------------------------------------------


#-----------------------------------------------------------
#                   Configuracion default
#-----------------------------------------------------------
Color('Azul',1)
Color('Amarillo',0)
B_Hilo_Comado   = threading.Thread(target=Blink)        #
B_Hilo_Entrada  = threading.Thread(target=Led_Izquierda)#
B_Hilo_Salir    = threading.Thread(target=Led_Derecha)  #
B_Hilo_Error    = threading.Thread(target=Led_Error)    #

#-----------------------------------------------------------
#               Pruebas de funcioanmiento
#-----------------------------------------------------------

Eventos_Led()

#-----------------------------------------------------------
#-----------------------------------------------------------
#                       RESUMEN y descripciones
#-----------------------------------------------------------
#-----------------------------------------------------------
