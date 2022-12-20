#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ---------------------------
# Importacion de los módulos
# ---------------------------

import pygame
from pygame.locals import *
import time
import lib.Control_Archivos2  as Ca

#-----------------------------------
#           Definiciones
#-----------------------------------
Leer_Archivo            = Ca.Leer_Archivo

#-----------------------------------
#    Variables de configuracion
#-----------------------------------
Texto_Display2 = 'Actualizando'
contador_progreso=0
CT = 40
Tama_Visualizar=10


# -----------
# Constantes
# -----------
SCREEN_WIDTH = 320
SCREEN_HEIGHT = 480

# ------------------------------
# Clases y Funciones utilizadas
# ------------------------------

def Procesos_A():
        
        res16 = Leer_Archivo(19) # Leer en donde va el proceso de actualizacion
        #print res16
        Faces =res16.split("\n")
        for Face in range(len(Faces)):
                c = Faces[Face]
                #print Face
                #print c
                c2 =c.split(" ")
                if len(c2[0]) >= 2:
                    #print len(c2[0])
                    #print c2[0]
                    Ultimo = c2[0]

        return Faces



# ------------------------------
#       Funcion principal 
# ------------------------------


def main():


    global contador_progreso
    global Texto_Display2
    global CT
    global Tama_Visualizar

    #-------------------------------------------------------------
    #              Inicioando Elementos Graficos
    #-------------------------------------------------------------
    print 'Iniciando Elementos Graficos'
    pygame.init()

    # Tamano de la ventana
    #screen = pygame.display.set_mode((SCREEN_WIDTH, SCREEN_HEIGHT))
    screen = pygame.display.set_mode((0,0), pygame.FULLSCREEN)
    pygame.display.set_caption("Actualizador")

    # cargamos el fondo y una imagen (se crea objetos "Surface")
    fondo       = pygame.image.load("/home/pi/Actualizador/img/Actualizando.png").convert_alpha()#.convert()
    fuente = pygame.font.SysFont("Arial", 20)
    screen.blit(fondo, (0, 0))  # pintando fondo
    pygame.display.flip()       # se muestran lo cambios en pantalla

    

    #-------------------------------------------------------------
    #              Ciclo programa principal
    #-------------------------------------------------------------

    while True:

        #------------------------------------------
        #           Contadores de progreso
        #------------------------------------------
        
        contador_progreso = contador_progreso +1
        
        #------------------------------------------
        #           tiempo de espera 
        #------------------------------------------
        
        time.sleep(0.05)

        #------------------------------------------
        #           Pintado del fondo
        #------------------------------------------
        
        pygame.draw.rect(screen,(255,255,255),[0,0,320,480])
        screen.blit(fondo, (20, -12))

        pygame.draw.rect(screen,(0,0,0),[0,250,320,480])
        
        if contador_progreso == CT :
                CT = CT+40
                Texto_Display2= Texto_Display2 + '.'

        if contador_progreso >= 40*20:
                contador_progreso = 0
                Texto_Display2 = 'Actualizando'
                CT=40
                
        mensaje = fuente.render(Texto_Display2, 1, (255, 255, 255))
        screen.blit(mensaje, (5, 250))

        Faces = Procesos_A()
        dist=0
        C_Faces = len(Faces)
        #print C_Faces
        Pintar =0
        
        if Tama_Visualizar < C_Faces:
                Pintar = C_Faces - Tama_Visualizar

        #print Pintar       
        for Face in range(C_Faces):
                
                if Face >= Pintar:
                        c = Faces[Face]
                        mensaje = fuente.render(c, 1, (255, 255, 255))
                        screen.blit(mensaje, (5, 268+dist))
                        dist=dist+18
        

        
        #--------------------------------------------------
        # se muestran lo cambios en pantalla
        #--------------------------------------------------
        pygame.display.flip()
        
        # Posibles entradas del teclado y mouse
        for event in pygame.event.get():

            if event.type == pygame.MOUSEBUTTONUP:    
                x,y = pygame.mouse.get_pos()
                


if __name__ == "__main__":
    main()
