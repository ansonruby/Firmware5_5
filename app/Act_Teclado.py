#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Libreria personal para el control del Buzzer.



# ideas a implementar







"""
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------
#                                   importar complementos
#---------------------------------------------------------------------------------------

import os, sys, time, commands
import pygame
from pygame.locals import *

#---------------------------------------------------------------------------------------
#                                   Librerias personale
#---------------------------------------------------------------------------------------

from lib.Lib_File import *                              # importar con los mismos nombres
from lib.Lib_Rout import *                              # importar con los mismos nombres
from lib.Lib_Networks import *                          # importar con los mismos nombres

#---------------------------------------------------------------------------------------
#                                   CONSTANTES
#---------------------------------------------------------------------------------------

#       Parametros  Ventana grafica

DEBUG_Teclado   = 1                                 # 0: ventana minimizada # 1: FULLSCREEN
SCREEN_WIDTH    = 320                               # Ancho
SCREEN_HEIGHT   = 480                               # Alto
win_pos_x       = 30                                # Coordenada en X
win_pos_y       = 35                                # Coordenada en y

#       Parametros  Tiempos de esperas

MIN_T_Espera    = 0.2                               # Timepo minimo antes de ver un evento  0.1 = 100 ms , 1 = 1 segundo
MAX_T_Espera    = 3                                 # Timepo maximo antes de ver un evento

#       Constantes graficas

#--- fondos

background_1    = ''                                #
background_2    = ''                                #

#--- estados

Denegado        = ''                                #
Permitido       = ''                                #
Per_Derecha     = ''                                #
Per_Izquierda   = ''                                #
Alerta          = ''                                #

#--- Fuentes de texto

Fuente_1        = ''                                #
Fuente_2        = ''                                #

#---------------------------------------------------------------------------------------
#                                   VARIABLES
#---------------------------------------------------------------------------------------

#--- para pausa periodica sin eventos

T_Espera        = MIN_T_Espera                      # tiempo de pausa antes de revisar un evento
NO_even         =0                                  # Contador de tiempo de ningun evento

#--- Para visualizacion de teclas

Memoria         = ""
Tamano          = 11
Texto_Display   = ""
Contador_Menu   = 0
operator        = ""

#--- Para Evento de informaccion del dispositivo

Estado_Informacion      = 0
Estados_visualizacion   = 0
Contador_Informacion    = 0
MAX_Constador_INF       = 80

#--- Para Evento de red

Contador_Red        = 0
Estado_visual_Red   = 0
MAX_Constador_Red   = 80

#--- Para Evento del Usuario

Estado_Usuario        = 0
Estado_visual_Usuario = 0

#--- Para Evento del QR repetido

Estado_QR                   = 0
Estado_visual_QR            = 0
Contador_QR_Repetido        = 0
MAX_Contador_QR_Repetido    = 5

#--- Para Evento de Forzar Firmware

Estado_Forzar_Firmware             = 0
Estado_visual_Forzar_Firmware      = 0
Contador_Inf_Forzar_Firmware       = 0
MAX_Constador_INF_Forzar_Firmware  = 80




#---------------------------------------------------------------------------------------
#                                   Funciones
#---------------------------------------------------------------------------------------

#---------------------------------------------------------------------------------------
#---------------------------------
#           Eventos del Teclado
#---------------------------------
#---------------------------------------------------------------------------------------

def Eventos():
    #------------------------------------------------
    #evento que muestar la informacion del dispsotivo
    #------------------------------------------------
    ET = -1                 # Bandera activacion Teclado
    EID = -1                # Bandera informacion dispositivo
    EFF = -1                # Bandera actualizacion de firmware
    EER = -1                # Bandera informacion red
    EEU = -1                # Bandera Estados de usuarios
    EEQ = -1                # Bandera Evento de estado de qr repetido
    #------------------------------------------------
    ET  = Evento_Teclado()
    EID = Evento_Informacion_Dispositivo()
    EER = Evento_Estado_Red()
    EEU = Evento_Estado_Usuario()
    EEQ = Evento_Estado_QR_Repetido()
    EFF = Evento_Forzar_Firmware()

    if EID != -1 or ET != -1  or EFF != -1  or EER != -1  or EEU != -1 or EEQ != -1: return 1           # repintar
    else                     : return -1                                                                # No pintar
    return -1                                                                                           # No pintar













#---------------------------------------------------------------------------------------
#---------------------------------
#           Funciones para  graficas
#---------------------------------
#---------------------------------------------------------------------------------------

#--- Inicialisacion de imagenes

def Inicializaciones_Graficas():
    global background_1
    global background_2
    global Denegado
    global Permitido
    global Per_Derecha
    global Per_Izquierda
    global Fuente_1
    global Fuente_2
    global Alerta

    Fuente_1 = pygame.font.SysFont("Arial", 20)
    Fuente_2 = pygame.font.SysFont("Arial", 40)
    background_1    = pygame.image.load(FONDO_1).convert()
    background_2    = pygame.image.load(FONDO_2).convert()

    Denegado      = pygame.image.load(Link_Denegado).convert_alpha()
    Denegado      = pygame.transform.scale(Denegado,(330,310))
    Permitido     = pygame.image.load(Link_Permitido).convert_alpha()
    Per_Derecha   = pygame.image.load(Link_Per_Derecha).convert_alpha()
    Per_Derecha   = pygame.transform.scale(Per_Derecha,(290,290))
    Per_Izquierda = pygame.transform.rotate(Per_Derecha,180)
    Alerta        = pygame.image.load(Link_Alerta).convert_alpha()

#--- funciona para tibujar todos los eventos y elmentos graficos

def Dibujar():
    global Texto_Display
    global Estados_visualizacion
    global Estado_visual_Red
    global Estado_visual_Usuario
    global Estado_visual_QR
    global Estado_visual_Forzar_Firmware

    Pintar_fondo(1)
    Pintar_Display(Texto_Display)

    if Estados_visualizacion  == 1:         Pintar_mensaje( 38, 70, Inf_Dispositivo())
    if Estado_visual_Red  == 1:             Pintar_Status_Red(GET_STatus_Red())    #Pintar_Status_Red(Get_File(STATUS_RED))        # hacer actualizador red
    if Estado_visual_QR  == 1:              Pintar_QR_Repetido()
    if Estado_visual_Usuario   == 1:        Pintar_Estados_Usuario( Get_File(STATUS_USER))
    if Estado_visual_Forzar_Firmware  == 1: Pintar_mensaje( 38, 70, "           Forzando\n       Actualizacion\n            Firmware\n")

    pygame.display.flip()

#--- Pintar fondos

def Pintar_fondo(a):

    global background_1
    global background_2
    if a == 1 : screen.blit(background_1, (0, 0))
    if a == 2 : screen.blit(background_2, (0, 0))

#--- Pintar Teclas digitadas

def Pintar_Display(Texto_Display):
    global Fuente_1
    fuente = Fuente_2
    mensaje = fuente.render(Texto_Display, 1, (255, 255, 255))
    screen.blit(mensaje, (40, 10))

#--- Pintar mensajes en cuadro azul

def Pintar_mensaje( x, y, texto):
    global Fuente_1

    pygame.draw.rect(screen,(32,112,164), (x,y-10, 245, 250))
    fuente = Fuente_1
    texto_en_lineas = texto.split('\n') # ejemplo: convierte "hola \n mundo" en ["hola ", " mundo"
    for linea in texto_en_lineas:
        nueva = fuente.render(linea, 1, (0,0,0))
        screen.blit(nueva, (x, y))
        y += nueva.get_height()















#---------------------------------------------------------------------------------------
#-----------------------------------------------------------
#----      Funciones para el control de ivernacion del teclado    ----
#-----------------------------------------------------------
#---------------------------------------------------------------------------------------

#--- Tiempo Espara Proceso

def Tiempo_Espara_Proceso():
    global T_Espera
    time.sleep(T_Espera)

#--- Dormir procesos

def Dormir_procesos():
    global T_Espera
    global MIN_T_Espera
    global NO_even
    NO_even= NO_even + 1
    if NO_even>=100:
        NO_even=0
        T_Espera = T_Espera + 0.1
        if T_Espera >= MAX_T_Espera:
            T_Espera = MAX_T_Espera

#--- Reinicio del tiempo del proceso

def Reset_Tiempo_proceso():
    global T_Espera
    T_Espera = MIN_T_Espera

#---------------------------------


















#---------------------------------------------------------------------------------------
#-----------------------------------------------------------
#----      Funciones para detecion de teclas y administracion de las mismos    ----
#-----------------------------------------------------------
#---------------------------------------------------------------------------------------

#--- funciones para verificar si se realizo clik en la posicion de teclas 0-9, k, OK, Borrar

def motion(x,y):
    Ix=40
    Iy=75
    Disx=75+10
    Disy=75+10

    if (x >= Ix+(Disx*0)) and (x<=Ix+75+(Disx*0)) and (y >= Iy+(Disy*0)-10) and (y <= Iy+70+(Disy*0)) : return 1    # "1"
    if (x >= Ix+(Disx*1)) and (x<=Ix+75+(Disx*1)) and (y >= Iy+(Disy*0)-10) and (y <= Iy+70+(Disy*0)) : return 2    # "2"
    if (x >= Ix+(Disx*2)) and (x<=Ix+75+(Disx*2)) and (y >= Iy+(Disy*0)-10) and (y <= Iy+70+(Disy*0)) : return 3    # "3"
    if (x >= Ix+(Disx*0)) and (x<=Ix+75+(Disx*0)) and (y >= Iy+(Disy*1)) and (y <= Iy+70+(Disy*1)) :    return 4    # "4"
    if (x >= Ix+(Disx*1)) and (x<=Ix+75+(Disx*1)) and (y >= Iy+(Disy*1)) and (y <= Iy+70+(Disy*1)) :    return 5    # "5"
    if (x >= Ix+(Disx*2)) and (x<=Ix+75+(Disx*2)) and (y >= Iy+(Disy*1)) and (y <= Iy+70+(Disy*1)) :    return 6    # "6"
    if (x >= Ix+(Disx*0)) and (x<=Ix+75+(Disx*0)) and (y >= Iy+(Disy*2)) and (y <= Iy+70+(Disy*2)) :    return 7    # "7"
    if (x >= Ix+(Disx*1)) and (x<=Ix+75+(Disx*1)) and (y >= Iy+(Disy*2)) and (y <= Iy+70+(Disy*2)) :    return 8    # "9"
    if (x >= Ix+(Disx*2)) and (x<=Ix+75+(Disx*2)) and (y >= Iy+(Disy*2)) and (y <= Iy+70+(Disy*2)) :    return 9    # "9"
    if (x >= Ix+(Disx*0)) and (x<=Ix+75+(Disx*0)) and (y >= Iy+(Disy*3)) and (y <= Iy+70+(Disy*3)) :    return 14   # "Borrar"
    if (x >= Ix+(Disx*1)) and (x<=Ix+75+(Disx*1)) and (y >= Iy+(Disy*3)) and (y <= Iy+70+(Disy*3)) :    return 0    # "0"
    if (x >= Ix+(Disx*2)) and (x<=Ix+75+(Disx*2)) and (y >= Iy+(Disy*3)) and (y <= Iy+70+(Disy*3)) :    return 11   # "K"
    if (x >= Ix+(Disx*0)) and (x<=Ix+75+(Disx*2)) and (y >= Iy+(Disy*4)) and (y <= Iy+70+(Disy*4)) :    return 12   # "OK"

    return -1

#--- funcion para  evento de los botones teclas 0-9 y k

def click_Tecla(number):
    global operator
    global Contador_Menu
    global Texto_Display
    global Memoria
    global Tamano
    global Estado_Informacion
    global Estado_Forzar_Firmware

    Set_File(COM_BUZZER, '1')      # activar sonido por 500*1
    if Contador_Menu == 3: # Numero de borrados
        if   number == 11: Estado_Forzar_Firmware  = 1 # Tecla 'K' print 'Forzar Actualizacion Firmware'
        elif number == 1 : Estado_Informacion      = 1 # Tecla '1' print 'ver informacion dispositivo'

    Contador_Menu=0

    if number == 11:    number = 'K'

    N_Teclas = len(operator)
    if N_Teclas > 0:
        operator=operator+str(number)
        Memoria = operator
    elif number != 0:
        operator=operator+str(number)
        Memoria = operator

    N_Teclas = len(operator)
    if N_Teclas >= Tamano: #print 'visualisar diferente'
        Memoria=Memoria[N_Teclas-Tamano:N_Teclas+1]

    Texto_Display = Memoria

#--- funcion para  evento del boton borrar

def clrbut():

    global operator
    global Contador_Menu
    global Texto_Display
    global Memoria

    Set_File(COM_BUZZER, '1')      # activar sonido por 500*1
    trama = len(operator)
    if trama > 0:
        operator=operator[:trama-1]
        Memoria = operator
    else:
        operator=""
        Memoria = operator
        Contador_Menu+=1

    N_Teclas = len(operator)
    if N_Teclas >= Tamano: #print 'visualisar diferente'
        Memoria=Memoria[N_Teclas-Tamano:N_Teclas+1]

    Texto_Display = Memoria
    #print Contador_Menu
    if Contador_Menu == 5:  # numero de veces para activar El Menu de Configuracion
        Contador_Menu = 0
        pygame.quit()
        commands.getoutput('python /home/pi/Firmware/app/Menu_Config.py')
        sys.exit()

#--- funcion para  evento del boton OK

def equlbut():  #para el boton OK  #hacer un hilo para procesar los ruts
    global operator
    global Contador_Menu
    global Texto_Display
    global Memoria

    Set_File(COM_BUZZER, '1')           # activar sonido por 500*1
    Contador_Menu=0
    if len(operator) > 0:
        Set_File(COM_TECLADO, operator) # escrivir en archivo para procesar
        #Set_File(COM_NFC, operator) # escrivir en archivo para procesar      # simulacion NFC
        operator=""
        Memoria=""
        Texto_Display  = operator
        Set_File(STATUS_TECLADO, '1')       # Estado de teckas para enviar a servidor
        #Set_File(STATUS_NFC, '1')           # simulacion NFC


#--- funcion principal de evento de botones

def Evento_Teclado():

    for event in pygame.event.get():
        if event.type == pygame.MOUSEBUTTONUP:
            x,y = pygame.mouse.get_pos()
            Tecla = motion(x,y)
            if      Tecla == -1: return -1          # Ninguna tecla
            elif    Tecla == 14: clrbut()           #Tecla Borrar
            elif    Tecla == 12: equlbut()          #Tecla OK
            else               : click_Tecla(Tecla) #Tecla 0-9 y K
            return 1

    return -1














#---------------------------------------------------------------------------------------
#-----------------------------------------------------------
#----      Funciones para la informacion del dispositivo----
#-----------------------------------------------------------
#---------------------------------------------------------------------------------------

#--- funcione informacion dispositivos

def Inf_Dispositivo():

    Firmware = ((Get_Line(INF_FIRMWARE, 1)).replace("\n","")).replace("\r","")
    Firmware =  Firmware.replace("# ","")     # version firmware
    Vercion = ((Get_Line(INF_VERCION, 1)).replace("\n","")).replace("\r","")
    Vercion =  Vercion.replace("# ","")     # version firmware
    Caracte         = ((Get_Line(INF_DISPO, 1)).replace("\n","")).replace("\r","")
    Consecutivo     = ((Get_Line(INF_DISPO, 3)).replace("\n","")).replace("\r","")
    ID = Caracte+'XXX'+Consecutivo

    Inf = '              '
    Inf += Firmware +   '\n'
    Inf += Vercion  +   '\n'
    Inf +='              Nombre\n'
    Inf +=commands.getoutput('hostname') +   '\n'
    Inf +='              Serial\n'
    Inf += ID       +   '\n'
    Inf +='              Conexion\n'

    IPS = commands.getoutput('hostname -I')
    IPS = IPS.split(' ')

    for linea in IPS:
        if len(linea)>=3: #mejorar a solo ipv4 e identificar
            # print linea.count('.')
            # print linea
            if linea.count('.') == 3: # IP con cuatro puntos
                Inf +='IP: '
                Inf +=linea
                Inf +='\n'

    return Inf

#--- funcion detecion de evento

def Evento_Informacion_Dispositivo():
    global Estado_Informacion
    global Contador_Informacion
    global Estados_visualizacion
    global MAX_Constador_INF

    if Estado_Informacion == 1:
        Contador_Informacion = Contador_Informacion + 1
        if Contador_Informacion == 1:                       # Avilitar visualizacion
            Estados_visualizacion =1
            return 1

        if Contador_Informacion == MAX_Constador_INF-2:     # Desavilitar visualizacion
            Estados_visualizacion =0
            return 1

        if Contador_Informacion >= MAX_Constador_INF:       # contador de timepo de duracion visualizacion
            Contador_Informacion = 0
            Estado_Informacion =0
            return 1

    return -1
















#---------------------------------------------------------------------------------------
#-----------------------------------------------------------
#----      Funciones para Evento de estado de la red  ----
#-----------------------------------------------------------
#---------------------------------------------------------------------------------------

#--- funcion estado de la red

def Evento_Estado_Red():
    global Contador_Red
    global Estado_visual_Red
    global MAX_Constador_Red

    Contador_Red = Contador_Red + 1

    if Contador_Red == 1:                           # Avilitar visualizacion
        Estado_visual_Red =1
        return 1

    if Contador_Red == int(MAX_Constador_Red/2):    # Desavilitar visualizacion
        Estado_visual_Red =0
        return 1

    if Contador_Red >= MAX_Constador_Red:           # contador de tiempo de duracion visualizacion
        Contador_Red = 0
        return 1

    return -1

#--- funcion Estados red

def Estados_Red(x, Texto):
    if   Texto == 'sin_eth' : Pintar_Estados_Red(x, 0, 0) # sin ethernet
    elif Texto == 'con_eth' : Pintar_Estados_Red(x, 1, 0) # con ethernet
    elif Texto == 'sin_wif' : Pintar_Estados_Red(x, 0, 1) # sin wifi
    elif Texto == 'con_wif' : Pintar_Estados_Red(x, 1, 1) # con wifi

#--- funcion pintar Estados red

def Pintar_Estados_Red(x1, Relleno, Tipo_comec):

    pygame.draw.circle(screen,(32,112,164),(5+(10)*x1, 475),5,Relleno)
    if Tipo_comec == 1 :    pygame.draw.line(screen,(0,0,0),(0+(10)*x1 , 475) ,(8+(10)*x1 , 475))

#--- funcion puntado completo de Estados red

def Pintar_Status_Red(red):
    if len(red) >= 3:
        for x1 in range(int(red[0])):
            conec= red[1+x1*2]+ red[2+x1*2]
            #print conec +' '+ str(x1)
            if conec == 'ED' :  Estados_Red(x1, 'sin_eth')    #Azul oscura ethernet desconectado
            elif conec == 'EC' : Estados_Red(x1, 'con_eth')    #Azul claro ethernet conectado
            elif conec == 'WD' : Estados_Red(x1, 'sin_wif')    #Azul oscura wifi desconectado
            elif conec == 'WC' : Estados_Red(x1, 'con_wif')    #Azul claro wifi conectado














#---------------------------------------------------------------------------------------
#-----------------------------------------------------------
#----      Funciones para Evento de estado del Usuairo ----
#-----------------------------------------------------------
#---------------------------------------------------------------------------------------

#---  Evento de estado del Usuario
def Evento_Estado_Usuario():
    #global Estado_Usuario
    global Estado_visual_Usuario

    Usuario = Get_File(STATUS_USER)

    if '6' ==  Usuario or '3' ==  Usuario or '4' ==  Usuario or 'Permitido' ==  Usuario:
        #Estado_Usuario = Usuario
        Estado_visual_Usuario = 1
        return 1
    else:
        Estado_visual_Usuario = 0
        return -1

#---   pintado de estados de los usaurios

def Pintar_Estados_Usuario(Usuario):
    if   Usuario == '6':            Pintar_Estado_Usuario('Denegar')
    elif Usuario == '3':            Pintar_Estado_Usuario('Per_Derecha')
    elif Usuario == '4':            Pintar_Estado_Usuario('Per_Izquierda')
    elif Usuario == 'Permitido':    Pintar_Estado_Usuario('Permitido')


#---   pintado de estados de usuarios

def Pintar_Estado_Usuario(Texto):
    global Denegado
    global Permitido
    global Per_Derecha
    global Per_Izquierda

    if Texto != 'Denegar'           : pygame.draw.rect(screen,(255,255,255),[20,5,285,465])
    if Texto == 'Denegar'           : screen.blit(Denegado, (-20, 70))
    if Texto == 'Permitido'         : screen.blit(Permitido, (20, 100))
    if Texto == 'Per_Derecha'       : screen.blit(Per_Derecha, (20, 100))
    if Texto == 'Per_Izquierda'     : screen.blit(Per_Izquierda, (20, 100))













#---------------------------------------------------------------------------------------
#-----------------------------------------------------------
#----      Funciones para Evento de QR Repetido ----
#-----------------------------------------------------------
#---------------------------------------------------------------------------------------

#---  Evento de QR Estado_QR_Repetido

def Evento_Estado_QR_Repetido():
    global Estado_QR
    global Estado_visual_QR
    global Contador_QR_Repetido
    global MAX_Contador_QR_Repetido

    QR = Get_File(STATUS_REPEAT_QR)

    if '2' ==  QR : # or '3' ==  Usuario or '4' ==  Usuario:
        Estado_QR = QR
        Estado_visual_QR = 1
        Contador_QR_Repetido = Contador_QR_Repetido +1
        if Contador_QR_Repetido >= MAX_Contador_QR_Repetido:
            Contador_QR_Repetido=0
            Set_File(STATUS_REPEAT_QR, '0')
            Estado_visual_QR = 0

        return 1
    else:
        Estado_visual_QR = 0
        return -1

#---  Pintado de QR Repetido

def Pintar_QR_Repetido():
    global Alerta
    screen.blit(Alerta, (0,0))











#---------------------------------------------------------------------------------------
#-----------------------------------------------------------
#----      Funciones para Evento de Forzar Firmware ----
#-----------------------------------------------------------
#---------------------------------------------------------------------------------------

#---  Evento de Forzar Firmware

def Evento_Forzar_Firmware():

    global Estado_Forzar_Firmware
    global Contador_Inf_Forzar_Firmware
    global Estado_visual_Forzar_Firmware
    global MAX_Constador_INF_Forzar_Firmware

    if Estado_Forzar_Firmware == 1:
        Contador_Inf_Forzar_Firmware = Contador_Inf_Forzar_Firmware + 1

        # Avilitar visualizacion
        if Contador_Inf_Forzar_Firmware == 1:
            Set_File(COM_ACTUALIZADOR, '1')   # cambiar estado para hacer la actualizacion de firmware
            Estado_visual_Forzar_Firmware =1
            return 1
        # Desavilitar visualizacion
        if Contador_Inf_Forzar_Firmware == MAX_Constador_INF_Forzar_Firmware-2:
            Estado_visual_Forzar_Firmware =0
            return 1
        # contador de timepo de duracion visualizacion
        if Contador_Inf_Forzar_Firmware >= MAX_Constador_INF_Forzar_Firmware:
            Contador_Inf_Forzar_Firmware = 0
            Estado_Forzar_Firmware =0
            return 1
    return -1


















#---------------------------------------------------------------------------------------
#-----------------------------------------------------------
#----      Funciones para el ciclo principal           ----
#-----------------------------------------------------------
#---------------------------------------------------------------------------------------

def Ciclo_Teclado():
    Inicializaciones_Graficas()
    Dibujar()
    while True:
        Tiempo_Espara_Proceso()
        Even = Eventos()
        if Even == 1:
            Dibujar()
            Reset_Tiempo_proceso()
        else:
            Dormir_procesos()
    pygame.quit()













#---------------------------------------------------------------------------------------
#                                   Configuracion local
#---------------------------------------------------------------------------------------

#-----      inicializacion de pygame   --------

pygame.init()

#-----      Configuracion de ventana   --------

if DEBUG_Teclado == 0:
    os.environ['SDL_VIDEO_WINDOW_POS'] = "%d,%d" % (win_pos_x, win_pos_y)
    screen = pygame.display.set_mode([SCREEN_WIDTH, SCREEN_HEIGHT])
else:
    screen = pygame.display.set_mode((0,0), pygame.FULLSCREEN)

#---------------------------------------------------------------------------------------
#                                   Ciclo del programa
#---------------------------------------------------------------------------------------

print 'Listo'
Ciclo_Teclado()

#---------------------------------------------------------------------------------------
#-----------------------------------------------------------
#                       RESUMEN y descripciones
#-----------------------------------------------------------
#---------------------------------------------------------------------------------------
