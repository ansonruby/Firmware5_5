# -*- coding: utf-8 -*-

import Tkinter
import ttk
from Tkinter import *

import socket
import fcntl
import struct
import commands

import lib.Control_Archivos
import lib.Control_Ethernet
import lib.Control_Fecha


# definiciones para el aplicativo principal -----------------


N_A_wifi                ='/etc/wpa_supplicant/wpa_supplicant.conf'
N_A_IP_Static           ='/etc/dhcpcd.conf'


Escrivir_Archivo2        = lib.Control_Archivos.Escrivir_Archivo
Leer_Archivo            = lib.Control_Archivos.Leer_Archivo
Borrar                  = lib.Control_Archivos.Borrar_Archivo
Escrivir                = lib.Control_Archivos.Escrivir_Archivo
Escrivir_Estados        = lib.Control_Archivos.Escrivir_Estados

Test_IP_Dom             = lib.Control_Ethernet.Test_IP_Dominio
Tiempo                  = lib.Control_Fecha.T_Actual
U_Activos               = lib.Control_Ethernet.Usuarios_Activos
Dominio_Valido          = lib.Control_Ethernet.Dominio_Valido



#-----------------------------------
#---------Variables de configuracion
#-----------------------------------


tk = Tk()
tk.geometry("320x480")
tk.geometry("+%d+%d" % (0,0))
#tk.config(background='Dark gray')
#tk.attributes("-fullscreen",True)


Fuente=("Arial",14,'bold')
Fuenteip=("Arial",22,'bold')
Fuentew=("Arial",20,'bold')
Fuente2=("Arial",16,'bold')

#dimenciones de botones menu principal

DX_b=100
DY_b= 20
#Ip static
textin  =StringVar()
textin2 =StringVar()
textin3 =StringVar()
textin4 =StringVar()
textin5 =StringVar()
textin6 =StringVar()

#dimenciones de botones menu principal
DX=35#16
DY=15#2 #5
BD=1

#distancia menu principal
Disxm=55
Disym=30#39


# posicion de botones
Ini_x=6
Ini_y=95
Disx=90#52
Disy=60#35#39

#dimenciones de botones ipstatica
DXip=33#16
DYip=10#2 #5

# posicion de botones ipstatica
Ini_xip=25
Ini_yip=115
Disxip=90#52
Disyip=60#35#39


operator=""
operator2=""
operator3=""
operator4=""
operator5=""
operator6=""
Mayusculas=0

# posicion de botones wifi
Ini_xw=6
Ini_yw=48 #95
Disxw=62
Disyw=46#39
#dimenciones de botones wifi
DXw=18
DYw=4 #5

# Multi torniquete
MIni_xip = 25
MDisxip  = 95
MIni_y   = 120
MDisyip  = 60


Tiempo_Torniquete = int (Leer_Archivo(30))

#-----------------------------------
#--------       funciones       ----
#-----------------------------------


def Escrivir_Archivo(Texto,a):

        global N_A_wifi
        global N_A_IP_Static

        if a==6:	arch	=	N_A_wifi

        archivo = open(arch, "a")
        #print(archivo.tell())
        archivo.write(Texto + "\n")
        #print(archivo.tell())
        archivo.close()


def Modificar_Archivo1(a,we):

        global N_A_wifi
        global N_A_IP_Static

        contador =0
        #we =2

        if a==0:	arch	=	N_A_wifi
        if a==1:	arch	=	N_A_IP_Static

        f = open (arch,'r')
        lineas = f.readlines()
        f.close()

        x=0
        T_fichero = len(lineas)
        print T_fichero
        print a

        f = open (arch,'w')
        for linea in lineas:

                if (linea[0]!='#') and (len(linea)>=4):
                        if (linea.find('interface')!=-1) or (linea.find('static')!=-1):
                                if (linea.find('option')==-1):
                                        if (linea.find('eth0')!=-1):
                                                contador =0
                                                wec = 1

                                        if (linea.find('wlan0')!=-1):
                                                contador =0
                                                wec = 0

                                        if contador>=0 and contador <=3:
                                                if we == wec:
                                                        print 'Eli: '+str(contador) + linea
                                                else:
                                                        #print str(contador) + linea
                                                        f.write(linea)
                                        contador =contador + 1

                                else:
                                        #print str(contador) + linea
                                        f.write(linea)
                        else:
                                #print str(contador) + linea
                                f.write(linea)
                else:
                        #print str(contador) + linea
                        f.write(linea)


        print 'colocando las ip statica'
        if we==0:
                f.write('interface wlan0'+'\n')
        else:
                f.write('interface eth0'+'\n')

        f.write('static ip_address='+ str(IP.get())+'\n')
        f.write('static routers='+ str(Gateway.get())+'\n')
        f.write('static domain_name_servers='+ str(Gateway.get())+'\n')

        f.close()


def Modificar_Archivo(a):

        global N_A_wifi
        global N_A_IP_Static


        if a==0:	arch	=	N_A_wifi
        if a==1:	arch	=	N_A_IP_Static



        f = open (arch,'r')
        lineas = f.readlines()
        f.close()

        x=0
        T_fichero = len(lineas)
        print T_fichero


        f = open (arch,'w')
        for linea in lineas:
                #f.write(linea)

                x+=1

                if  x >= (T_fichero -3) :
                        #if len(linea) >= 1:
                        #(linea.find('interface')!=-1) or (linea.find('static')!=-1) or
                        if (linea[0]!='#') and (len(linea)>=2):
                                print 'Eliminar Linea:'+str(x)+': '+ linea
                                #f.write(linea)

                        else:
                                print 'Linea:'+str(x)+': '+ linea
                                #print 'Linea:'+str(x)+': '+ linea + 'Ta: '+str(len(linea))
                                f.write(linea)
                else:
                        f.write(linea)


        print 'colocando las ip statica'


        #f.write('interface wlan0'+'\n')
        f.write('interface eth0'+'\n')
        f.write('static ip_address='+ str(IP.get())+'\n')
        f.write('static routers='+ str(Gateway.get())+'\n')
        f.write('static domain_name_servers='+ str(Gateway.get())+'\n')

        f.close()


        #return mensaje
def clickbut_Tiempo(number):
        global Tiempo_Torniquete
        if number == '◄':
                Tiempo_Torniquete =Tiempo_Torniquete-1
                if Tiempo_Torniquete <= 1:
                        Tiempo_Torniquete =1

        else:
                Tiempo_Torniquete =Tiempo_Torniquete+1
                if Tiempo_Torniquete >= 9:
                        Tiempo_Torniquete = 9

        #operator=operator+str(number)
        #textin.set(operator)
        #P_C_Tiempo_Torniquete.set("2")
        texto = StringVar()
        texto.set(str(Tiempo_Torniquete))
        P_C_Tiempo_Torniquete.config(textvariable=texto)
        #Tiempo Torniquete
        Borrar(30)      #Esatado chicharra
        Escrivir_Estados(str(Tiempo_Torniquete),30)

def clickbut(number):   #lambda:clickbut(1)

        global operator
        global operator2
        global operator3
        global operator4
        global operator5
        global operator6
        global Mayusculas




        #print lista.get()
        """
        if number == '+':
                if Mayusculas == 0:
                        Mayusculas=1
                            #print "Minusculas"
                else:
                        Mayusculas=0
                        #print "Mayusculas"
        """
        if number == '◄':
                print 'borrar el ultimo'
                w=tk.focus_get()
                if w is IP:
                        IP.delete(len(IP.get())-1, END)
                        operator=IP.get()
                elif w is Gateway:
                        Gateway.delete(len(Gateway.get())-1, END)
                        operator2=Gateway.get()
                if w is wifi:
                        wifi.delete(len(wifi.get())-1, END)
                        operator3=wifi.get()
                elif w is contrasena:
                        contrasena.delete(len(contrasena.get())-1, END)
                        operator4=contrasena.get()
                elif w is M_T_IP:
                        M_T_IP.delete(len(M_T_IP.get())-1, END)
                        operator5=M_T_IP.get()

                elif w is Nuevo_Servidor:
                        Nuevo_Servidor.delete(len(Nuevo_Servidor.get())-1, END)
                        operator6=Nuevo_Servidor.get()


        else:

                if Mayusculas == 0:
                    number= number.upper()

                w=tk.focus_get()
                #print "focus is:",w
                #print type(w)
                #print wifi
                if w is IP:
                    #print "It's wifi"
                    if len(operator) > 0:
                        operator=operator+str(number)
                        textin.set(operator)
                        #sonidoLector(Tiempo_sonido)
                    elif number != 0:
                        operator=operator+str(number)
                        textin.set(operator)

                elif w is Gateway:
                    #print "It's contrasena"
                    if len(operator2) > 0:
                        operator2=operator2+str(number)
                        textin2.set(operator2)
                        #sonidoLector(Tiempo_sonido)
                    elif number != 0:
                        operator2=operator2+str(number)
                        textin2.set(operator2)

                elif w is wifi:
                    #print "It's contrasena"
                    if len(operator3) > 0:
                        operator3=operator3+str(number)
                        textin3.set(operator3)
                        #sonidoLector(Tiempo_sonido)
                    elif number != 0:
                        operator3=operator3+str(number)
                        textin3.set(operator3)
                elif w is contrasena:
                    #print "It's contrasena"
                    if len(operator4) > 0:
                        operator4=operator4+str(number)
                        textin4.set(operator4)
                        #sonidoLector(Tiempo_sonido)
                    elif number != 0:
                        operator4=operator4+str(number)
                        textin4.set(operator4)
                elif w is M_T_IP:
                    #print "It's contrasena"
                    if len(operator5) > 0:
                        operator5=operator5+str(number)
                        textin5.set(operator5)
                        #sonidoLector(Tiempo_sonido)
                    elif number != 0:
                        operator5=operator5+str(number)
                        textin5.set(operator5)
                elif w is Nuevo_Servidor:
                    #print "It's contrasena"
                    if len(operator6) > 0:
                        operator6=operator6+str(number)
                        textin6.set(operator6)
                        #sonidoLector(Tiempo_sonido)
                    elif number != 0:
                        operator6=operator6+str(number)
                        textin6.set(operator6)




def desplegar(event):
        Actualizar_lista()
        #print 'desplicada'
        return 0

def Actualizar_lista():
        lista["values"]= []
        #print 'Listado Wifis '
        res = commands.getoutput('sudo iwlist wlan0 scan | grep ESSID')
        res=res.replace('"',"")
        res=res.replace('\n',"")
        redes =res.split("ESSID:")

        BK_Red=0
        for x1 in range(len(redes)):
            c= redes[x1]
            c=c.replace('\n',"")
            c=c.replace(' ',"")
            #print (c)
            #lista.set(c)
            values = list(lista["values"])
            lista["values"]= values+ [c]

def ver_wifi_Letras_Minusculas():
        butqw.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*1))
        butww.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*1))
        butew.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*1))
        butrw.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*1))
        buttw.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*1))
        butyw.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*2))
        butuw.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*2))
        butiw.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*2))
        butow.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*2))
        butpw.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*2))
        butaw.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*3))
        butsw.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*3))
        butdw.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*3))
        butfw.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*3))
        butgw.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*3))
        buthw.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*4))
        butjw.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*4))
        butkw.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*4))
        butlw.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*4))
        butzw.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*4))
        butxw.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*5))
        butcw.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*5))
        butvw.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*5))
        butbw.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*5))
        butnw.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*5))
        butMYw.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*6))
        butmw.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*6))
        but123w.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*6))
        butabcw.place_forget()
        #butbw.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*6))
        butBow.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*6))
        butespw.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*7))

def NO_ver_wifi_Letras_Minusculas():
        butqw.place_forget()
        butww.place_forget()
        butew.place_forget()
        butrw.place_forget()
        buttw.place_forget()
        butyw.place_forget()
        butuw.place_forget()
        butiw.place_forget()
        butow.place_forget()
        butpw.place_forget()
        butaw.place_forget()
        butsw.place_forget()
        butdw.place_forget()
        butfw.place_forget()
        butgw.place_forget()
        buthw.place_forget()
        butjw.place_forget()
        butkw.place_forget()
        butlw.place_forget()
        butzw.place_forget()
        butxw.place_forget()
        butcw.place_forget()
        butvw.place_forget()
        butbw.place_forget()
        butnw.place_forget()
        butmw.place_forget()

def NO_ver_wifi_Letras_Mayusculas():
        butQw.place_forget()
        butWw.place_forget()
        butEw.place_forget()
        butRw.place_forget()
        butTw.place_forget()
        butYw.place_forget()
        butUw.place_forget()
        butIw.place_forget()
        butOw.place_forget()
        butPw.place_forget()
        butAw.place_forget()
        butSw.place_forget()
        butDw.place_forget()
        butFw.place_forget()
        butGw.place_forget()
        butHw.place_forget()
        butJw.place_forget()
        butKw.place_forget()
        butLw.place_forget()
        butZw.place_forget()
        butXw.place_forget()
        butCw.place_forget()
        butVw.place_forget()
        butBw.place_forget()
        butNw.place_forget()
        butMw.place_forget()

def NO_ver_wifi_Numeros():
        but1w.place_forget()
        but2w.place_forget()
        but3w.place_forget()
        but4w.place_forget()
        but5w.place_forget()
        but6w.place_forget()
        but7w.place_forget()
        but8w.place_forget()
        but9w.place_forget()
        but0w.place_forget()

        butA1w.place_forget()
        butS2w.place_forget()
        butD3w.place_forget()
        butF4w.place_forget()
        butG5w.place_forget()
        butH6w.place_forget()
        butJ7w.place_forget()
        butK8w.place_forget()
        butL9w.place_forget()
        butZ0w.place_forget()
        butX1w.place_forget()
        butC2w.place_forget()
        butV3w.place_forget()
        butB4w.place_forget()
        butN5w.place_forget()



def V_wifi_Minusculas():
        global Mayusculas

        if Mayusculas != 1 :
                Mayusculas=1


        No_ver_menu_principal()

        L_wifi.place(bordermode=OUTSIDE, height=20, width=100, y=25)
        L_password.place(bordermode=OUTSIDE, height=20, width=100, y=60)
        #wifi.place(bordermode=OUTSIDE, height=30, width=200, x=90, y=20)
        lista.place(x=Ini_xw+(Disxw*0)+83, y=Ini_yw+(Disyw*0)-35)
        contrasena.place(bordermode=OUTSIDE, height=29, width=200, x=89, y=55)

        P_Menu.place(x=Ini_x+150, y=Ini_y+330)#place(x=Ini_x+(Disx*1)+25, y=Ini_y+(Disy*9)+10)
        Aceptar_W.place(x=Ini_x, y=Ini_y+330)#place(x=Ini_x+(Disx*1)+25, y=Ini_y+(Disy*7)+33)
        #wifi

        #minusculas
        ver_wifi_Letras_Minusculas()
        #Maysculas
        NO_ver_wifi_Letras_Mayusculas()
        #numeros
        NO_ver_wifi_Numeros()



def  V_wifi_May_Minu():
        global Mayusculas
        if Mayusculas == 1 :
                Mayusculas=0
                V_wifi_Mayusculas()
        else:
                V_wifi_Minusculas()
                Mayusculas=1


def  V_wifi_Numeros():

        butabcw.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*6))

        but123w.place_forget()
        butMYw.place_forget()

        NO_ver_wifi_Letras_Mayusculas()

        NO_ver_wifi_Letras_Minusculas()


        but1w.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*1))
        but2w.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*1))
        but3w.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*1))
        but4w.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*1))
        but5w.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*1))
        but6w.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*2))
        but7w.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*2))
        but8w.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*2))
        but9w.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*2))
        but0w.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*2))

        butA1w.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*3))
        butS2w.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*3))
        butD3w.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*3))
        butF4w.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*3))
        butG5w.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*3))
        butH6w.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*4))
        butJ7w.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*4))
        butK8w.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*4))
        butL9w.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*4))
        butZ0w.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*4))
        butX1w.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*5))

        butC2w.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*5))
        butV3w.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*5))
        butB4w.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*5))
        butN5w.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*5))
        #butMYw.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*6))
        #butmw.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*6))


def V_wifi_Mayusculas():
        global Mayusculas
        if Mayusculas != 0 :
                Mayusculas=0

        L_Menu_Principal.place_forget()
        P_wifi.place_forget()
        P_IP.place_forget()
        P_salir.place_forget()
        P_Menu.place(x=Ini_x+150, y=Ini_y+330)#P_Menu.place(x=Ini_x+(Disx*1)+25, y=Ini_y+(Disy*9))
        #wifi
        NO_ver_wifi_Letras_Minusculas()

        butQw.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*1))
        butWw.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*1))
        butEw.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*1))
        butRw.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*1))
        butTw.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*1))
        butYw.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*2))
        butUw.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*2))
        butIw.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*2))
        butOw.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*2))
        butPw.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*2))
        butAw.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*3))
        butSw.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*3))
        butDw.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*3))
        butFw.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*3))
        butGw.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*3))
        butHw.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*4))
        butJw.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*4))
        butKw.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*4))
        butLw.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*4))
        butZw.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*4))
        butXw.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*5))
        butCw.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*5))
        butVw.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*5))
        butBw.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*5))
        butNw.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*5))
        butMw.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*6))
        butespw.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*7))

        NO_ver_wifi_Numeros()


def V_IP():
        #Menu Principal
        No_ver_menu_principal()
        #P_Menu.place(x=Ini_x+(Disx*0)+25, y=Ini_y+(Disy*0)) # 1 9
        P_Menu.place(x=Ini_x+150, y=Ini_y+330) # 1 9
        #IP_static
        ver_IP_Static()


def ver_IP_Static():

        L_Ip_Static.place(bordermode=OUTSIDE, height=20, width=100, y=10, x= 115)
        L_Ip_Static_lista.place(bordermode=OUTSIDE, height=29, width=200, x=60, y=40)
        L_Ip.place(bordermode=OUTSIDE, height=20, width=100, y=80)
        L_Gat.place(bordermode=OUTSIDE, height=20, width=100, y=130)
        IP.place(bordermode=OUTSIDE, height=30, width=200, x=90, y=80)
        Gateway.place(bordermode=OUTSIDE, height=30, width=200, x=90, y=120)

        but1.place(x=Ini_xip+(Disxip*0), y=Ini_yip+(Disyip*1))
        but2.place(x=Ini_xip+(Disxip*1), y=Ini_yip+(Disyip*1))
        but3.place(x=Ini_xip+(Disxip*2), y=Ini_yip+(Disyip*1))
        but4.place(x=Ini_xip+(Disxip*0), y=Ini_yip+(Disyip*2))
        but5.place(x=Ini_xip+(Disxip*1), y=Ini_yip+(Disyip*2))
        but6.place(x=Ini_xip+(Disxip*2), y=Ini_yip+(Disyip*2))
        but7.place(x=Ini_xip+(Disxip*0), y=Ini_yip+(Disyip*3))
        but8.place(x=Ini_xip+(Disxip*1), y=Ini_yip+(Disyip*3))
        but9.place(x=Ini_xip+(Disxip*2), y=Ini_yip+(Disyip*3))
        but0.place(x=Ini_xip+(Disxip*0), y=Ini_yip+(Disyip*4))
        butb.place(x=Ini_xip+(Disxip*1), y=Ini_yip+(Disyip*4))
        butp.place(x=Ini_xip+(Disxip*2), y=Ini_yip+(Disyip*4))
        Aceptar_IP.place(x=Ini_x, y=Ini_y+330)



def No_ver_IP_Static():
        L_Ip_Static.place_forget()
        L_Ip_Static_lista.place_forget()
        L_Ip.place_forget()
        L_Gat.place_forget()
        IP.place_forget()
        Gateway.place_forget()
        but1.place_forget()
        but2.place_forget()
        but3.place_forget()
        but4.place_forget()
        but5.place_forget()
        butb.place_forget()
        but6.place_forget()
        but7.place_forget()
        but8.place_forget()
        but9.place_forget()
        but0.place_forget()
        butp.place_forget()
        Aceptar_IP.place_forget()
        #Cancelar_IP.place_forget()

def L_menu_inicio():
        #Menu
        ver_menu_principal()
        P_Menu.place_forget()
        #IP_static
        No_ver_IP_Static()
        #wifi
        L_wifi.place_forget()
        L_password.place_forget()
        butabcw.place_forget()
        wifi.place_forget()
        contrasena.place_forget()
        Aceptar_W.place_forget()
        lista.place_forget()

        NO_ver_wifi_Letras_Mayusculas()

        NO_ver_wifi_Letras_Minusculas()

        NO_ver_wifi_Numeros()

        but123w.place_forget()
        butabcw.place_forget()
        butbw.place_forget()
        butBow.place_forget()
        butespw.place_forget()
        butMYw.place_forget()

        No_ver_Restablecer()
        No_ver_Torniquete()
        No_ver_Multi_Torniquete()

        NO_ver_Nuevo_Servidor_Letras_Mayusculas()
        NO_ver_Nuevo_Servidor_Letras_Minusculas()
        NO_ver_Nuevo_Servidor_Numeros()


        but123S.place_forget()
        butabcS.place_forget()
        butbS.place_forget()
        butBoS.place_forget()
        butespS.place_forget()
        butMYS.place_forget()

        L_Nuevo_Servidor.place_forget()
        Nuevo_Servidor.place_forget()
        Aceptar_Nuevo_Servidor.place_forget()
        Test_Nuevo_Servidor.place_forget()


def check_IP(address):
        try:
                socket.inet_aton(address)
                return address.count('.') == 3
        except socket.error:
                return False

def salir():

        commands.getoutput('sudo reboot')


def verificar_IP_Static(): #esta función verifica que este correcto usuario y contraseña digitado por el usuario

    Ip1=IP.get()#get es el metodo utilizado para capturar los datos de la caja de texto
    Gateway1=Gateway.get()
    Tipo_red = L_Ip_Static_lista.get()
    print Tipo_red
    print Ip1
    print Gateway1

    #Leer_Archivo(1)
    #print len(a)
    #print len(Tipo_red)



    if (len(Ip1) == 0) or (len(Gateway1)==0) or (len(Tipo_red)==0):
        top = Tk()
        top.geometry("+%d+%d" % (65,200))
        top.config(background='Red')
        top.title("Error")
        frame2 = Message(top, font='Arial', relief=RAISED, text='Los campos estan vacíos.',padx=50,pady=50,width=100, bg='Red')
        frame2.pack()
    else:
        print 'verificacion ip valida'

        if (check_IP(Ip1) == False) or (check_IP(Gateway1) == False) :
                top = Tk()
                top.geometry("+%d+%d" % (65,200))
                top.config(background='Red')
                top.title("Error")
                frame2 = Message(top, font='Arial', relief=RAISED, text='NO es una IP valida.',padx=50,pady=50,width=100, bg='Red')
                frame2.pack()
        else:
                print 'verificar una configuracion previa y guardar la nueva'
                #Modificar_Archivo(1)
                if Tipo_red == "Ethernet":
                        Modificar_Archivo1(1,1)
                else:
                        Modificar_Archivo1(1,0)
                commands.getoutput('sudo reboot')



def verificar_wifi(): #esta función verifica que este correcto usuario y contraseña digitado por el usuario

    #red=wifi.get()#get es el metodo utilizado para capturar los datos de la caja de texto
    clave=contrasena.get()

    red = lista.get()
    print red

    #print len(a)
    #print len(b)

    if (len(red) == 0) or (len(clave)==0):
        top = Tk()
        top.geometry("+%d+%d" % (65,200))
        top.config(background='Red')
        top.title("Error")
        frame2 = Message(top, font='Arial', relief=RAISED, text='Los campos estan vacíos.',padx=50,pady=50,width=100, bg='Red')
        frame2.pack()
    else:
        print 'Test wifis '
        res = commands.getoutput('sudo iwlist wlan0 scan | grep ESSID')
        res=res.replace('"',"")
        res=res.replace('\n',"")
        redes =res.split("ESSID:")

        BK_Red=0
        for x1 in range(len(redes)):
            c= redes[x1]
            c=c.replace('\n',"")
            c=c.replace(' ',"")
            print (c)
            #print len(c)
            if red == c:
                #print 'Esta al alcanse la red'
                BK_Red=1

        if BK_Red == 0:
            top = Tk()
            top.geometry("+%d+%d" % (65,200))
            top.config(background='Red')
            top.title("Error")
            frame2 = Message(top, font='Arial', relief=RAISED, text='La red no esta disponible.',padx=50,pady=50,width=100, bg='Red')
            frame2.pack()
        else:
            print 'Configurar el archivo wifi '


            commands.getoutput('sudo chmod -R 777 /etc/wpa_supplicant/wpa_supplicant.conf')

            Nueva_wifi='\nnetwork={\n\tssid="'+red+'"\n\tpsk="'+clave+'"\n\tkey_mgmt=WPA-PSK\n\n}'
            print (Nueva_wifi)

            Escrivir_Archivo(Nueva_wifi,6)

            commands.getoutput('sudo reboot')

def ver_menu_principal():
        L_Menu_Principal.place(bordermode=OUTSIDE, height=20, width=150, y=10, x= 90)
        P_wifi.place(x=Ini_x+(Disxm*0)+25, y=Ini_y+(Disym*0)-60)
        P_IP.place(x=Ini_x+(Disxm*0)+24, y=Ini_y+(Disym*2)-50)
        P_Restablecer.place(x=Ini_x+(Disxm*0)+25, y=Ini_y+(Disym*4)-40)
        P_Confi_Torniquete.place(x=Ini_x+(Disxm*0)+25, y=Ini_y+(Disym*6)-30)
        P_Confi_Multi_Dispositivo.place(x=Ini_x+(Disxm*0)+25, y=Ini_y+(Disym*7)+10)
        P_salir.place(x=Ini_x+(Disxm*0)+25, y=Ini_y+(Disym*10)-0)

def No_ver_menu_principal():
        L_Menu_Principal.place_forget()
        P_wifi.place_forget()
        P_IP.place_forget()
        P_Restablecer.place_forget()
        P_Confi_Torniquete.place_forget()
        P_salir.place_forget()
        P_Confi_Multi_Dispositivo.place_forget()

def Restablecer():
        #Menu Principal
        No_ver_menu_principal()
        P_Menu.place(x=Ini_x+150, y=Ini_y+330)#P_Menu.place(x=Ini_x+(Disx*1)+25, y=Ini_y+(Disy*9))
        #Botones Restablecer
        P_R_Restablecer.place(bordermode=OUTSIDE, height=20, width=150, y=10, x= 90)
        P_R_Borrar_Historial.place(x=Ini_x+(Disx*0)+25, y=Ini_y+(Disy*0)-50)
        P_R_Borrar_Bace_Datos.place(x=Ini_x+(Disx*0)+25, y=Ini_y+(Disy*1)-40)
        P_R_Valores_Fabrica.place(x=Ini_x+(Disx*0)+25, y=Ini_y+(Disy*2)-30)
        P_R_Nuevo_Servidor.place(x=Ini_x+(Disx*0)+25, y=Ini_y+(Disy*3)-20)

        P_R_Aceptar_Res.place(x=Ini_x, y=Ini_y+330)

        #print "restableser"

def No_ver_Restablecer():

        #Botones Restablecer
        P_R_Restablecer.place_forget()
        P_R_Valores_Fabrica.place_forget()
        P_R_Borrar_Bace_Datos.place_forget()
        P_R_Borrar_Historial.place_forget()
        P_R_Nuevo_Servidor.place_forget()
        P_R_Aceptar_Res.place_forget()

def NO_ver_Nuevo_Servidor_Letras_Mayusculas():
        butQS.place_forget()
        butWS.place_forget()
        butES.place_forget()
        butRS.place_forget()
        butTS.place_forget()
        butYS.place_forget()
        butUS.place_forget()
        butIS.place_forget()
        butOS.place_forget()
        butPS.place_forget()
        butAS.place_forget()
        butSS.place_forget()
        butDS.place_forget()
        butFS.place_forget()
        butGS.place_forget()
        butHS.place_forget()
        butJS.place_forget()
        butKS.place_forget()
        butLS.place_forget()
        butZS.place_forget()
        butXS.place_forget()
        butCS.place_forget()
        butVS.place_forget()
        butBS.place_forget()
        butNS.place_forget()
        butMS.place_forget()

def NO_ver_Nuevo_Servidor_Letras_Minusculas():
        butqS.place_forget()
        butwS.place_forget()
        buteS.place_forget()
        butrS.place_forget()
        buttS.place_forget()
        butyS.place_forget()
        butuS.place_forget()
        butiS.place_forget()
        butoS.place_forget()
        butpS.place_forget()
        butaS.place_forget()
        butsS.place_forget()
        butdS.place_forget()
        butfS.place_forget()
        butgS.place_forget()
        buthS.place_forget()
        butjS.place_forget()
        butkS.place_forget()
        butlS.place_forget()
        butzS.place_forget()
        butxS.place_forget()
        butcS.place_forget()
        butvS.place_forget()
        butbS.place_forget()
        butnS.place_forget()
        butmS.place_forget()

def ver_Nuevo_Servidor_Letras_Minusculas():
        butqS.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*1))
        butwS.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*1))
        buteS.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*1))
        butrS.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*1))
        buttS.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*1))
        butyS.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*2))
        butuS.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*2))
        butiS.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*2))
        butoS.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*2))
        butpS.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*2))
        butaS.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*3))
        butsS.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*3))
        butdS.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*3))
        butfS.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*3))
        butgS.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*3))
        buthS.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*4))
        butjS.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*4))
        butkS.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*4))
        butlS.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*4))
        butzS.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*4))
        butxS.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*5))
        butcS.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*5))
        butvS.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*5))
        butbS.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*5))
        butnS.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*5))
        butMYS.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*6))
        butmS.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*6))
        but123S.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*6))
        butabcS.place_forget()
        #butbw.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*6))
        butBoS.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*6))
        butespS.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*7))

def ver_Nuevo_Servidor_Letras_Mayusculas():
        global Mayusculas
        if Mayusculas != 0 :
                Mayusculas=0

        #L_Menu_Principal.place_forget()
        #P_wifi.place_forget()
        #P_IP.place_forget()
        #P_salir.place_forget()
        #P_Menu.place(x=Ini_x+150, y=Ini_y+330)#P_Menu.place(x=Ini_x+(Disx*1)+25, y=Ini_y+(Disy*9))
        #wifi
        NO_ver_Nuevo_Servidor_Letras_Minusculas()

        butQS.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*1))
        butWS.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*1))
        butES.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*1))
        butRS.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*1))
        butTS.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*1))
        butYS.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*2))
        butUS.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*2))
        butIS.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*2))
        butOS.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*2))
        butPS.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*2))
        butAS.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*3))
        butSS.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*3))
        butDS.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*3))
        butFS.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*3))
        butGS.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*3))
        butHS.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*4))
        butJS.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*4))
        butKS.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*4))
        butLS.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*4))
        butZS.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*4))
        butXS.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*5))
        butCS.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*5))
        butVS.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*5))
        butBS.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*5))
        butNS.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*5))
        butMS.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*6))
        butespS.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*7))

        NO_ver_Nuevo_Servidor_Numeros()

def  V_Nuevo_Servidor_Numeros():

        butabcS.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*6))

        but123S.place_forget()
        butMYS.place_forget()

        NO_ver_Nuevo_Servidor_Letras_Mayusculas()

        NO_ver_Nuevo_Servidor_Letras_Minusculas()


        but1S.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*1))
        but2S.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*1))
        but3S.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*1))
        but4S.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*1))
        but5S.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*1))
        but6S.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*2))
        but7S.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*2))
        but8S.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*2))
        but9S.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*2))
        but0S.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*2))

        butA1S.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*3))
        butS2S.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*3))
        butD3S.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*3))
        butF4S.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*3))
        butG5S.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*3))
        butH6S.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*4))
        butJ7S.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*4))
        butK8S.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*4))
        butL9S.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*4))
        butZ0S.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*4))
        butX1S.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*5))

        butC2S.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*5))
        butV3S.place(x=Ini_xw+(Disxw*2), y=Ini_yw+(Disyw*5))
        butB4S.place(x=Ini_xw+(Disxw*3), y=Ini_yw+(Disyw*5))
        butN5S.place(x=Ini_xw+(Disxw*4), y=Ini_yw+(Disyw*5))
        #butMYw.place(x=Ini_xw+(Disxw*0), y=Ini_yw+(Disyw*6))
        #butmw.place(x=Ini_xw+(Disxw*1), y=Ini_yw+(Disyw*6))

def NO_ver_Nuevo_Servidor_Numeros():
        but1S.place_forget()
        but2S.place_forget()
        but3S.place_forget()
        but4S.place_forget()
        but5S.place_forget()
        but6S.place_forget()
        but7S.place_forget()
        but8S.place_forget()
        but9S.place_forget()
        but0S.place_forget()

        butA1S.place_forget()
        butS2S.place_forget()
        butD3S.place_forget()
        butF4S.place_forget()
        butG5S.place_forget()
        butH6S.place_forget()
        butJ7S.place_forget()
        butK8S.place_forget()
        butL9S.place_forget()
        butZ0S.place_forget()
        butX1S.place_forget()
        butC2S.place_forget()
        butV3S.place_forget()
        butB4S.place_forget()
        butN5S.place_forget()


def V_Nuevo_Servidor_May_Minu():
        global Mayusculas
        if Mayusculas == 1 :
                Mayusculas=0
                ver_Nuevo_Servidor_Letras_Mayusculas()
        else:
                V_Nuevo_Servidor_Minusculas()
                Mayusculas=1


def Ver_Nuevo_Servidor():
        global Mayusculas

        if Mayusculas != 1 :
                Mayusculas=1


        No_ver_Restablecer()
        #L_Nuevo_Servidor.place(bordermode=OUTSIDE, height=20, width=100, y=25)
        #Nuevo_Servidor.place(bordermode=OUTSIDE, height=20, width=100, y=25)
        P_Menu.place(x=Ini_x+150, y=Ini_y+330)#P_Menu.place(x=Ini_x+(Disx*1)+25, y=Ini_y+(Disy*9))

        V_Nuevo_Servidor_Minusculas()

def V_Nuevo_Servidor_Minusculas():
        global Mayusculas

        if Mayusculas != 1 :
                Mayusculas=1


        No_ver_menu_principal()



        L_Nuevo_Servidor.place(bordermode=OUTSIDE, height=20, width=100, y=25)

        #L_password.place(bordermode=OUTSIDE, height=20, width=100, y=60)
        Nuevo_Servidor.place(bordermode=OUTSIDE, height=30, width=200, x=90, y=20)
        #lista.place(x=Ini_xw+(Disxw*0)+83, y=Ini_yw+(Disyw*0)-35)
        #contrasena.place(bordermode=OUTSIDE, height=29, width=200, x=89, y=55)

        P_Menu.place(x=Ini_x+150, y=Ini_y+330)#place(x=Ini_x+(Disx*1)+25, y=Ini_y+(Disy*9)+10)
        Aceptar_Nuevo_Servidor.place(x=Ini_x, y=Ini_y+330)#place(x=Ini_x+(Disx*1)+25, y=Ini_y+(Disy*7)+33)
        Test_Nuevo_Servidor.place(x=Ini_x+90, y=Ini_y-42)
        #wifi

        #minusculas
        ver_Nuevo_Servidor_Letras_Minusculas()
        #Maysculas
        NO_ver_Nuevo_Servidor_Letras_Mayusculas()
        #numeros
        NO_ver_Nuevo_Servidor_Numeros()

"""
def Dominio_Valido(Dominio):

        Resolver = "host -t A  " + Dominio + "   | grep address | awk {'print $4'}"
        address = commands.getoutput(Resolver)
        #print  address
        try:
                socket.inet_aton(address)
                if address.count('.') == 3:
                    print 'Dominio Valido'
                    return address
                else :  return False
        except socket.error:
                print 'NO contesta el dominio'
                return False
"""
def Check_Respuestas(Respuesta):
    #print Respuesta
    #print Respuesta.status_code
    if Respuesta == 'OK':
        print 'Respuesta correcta'
        return True
    else:
        print 'Respuesta incorrecta'
        #print Respuesta.text
        return False

    """
    if Respuesta.status_code == 200:
        if Respuesta.text == 'OK':
            print 'Respuesta correcta'
            return True
        else:
            print 'Respuesta incorrecta'
            #print Respuesta.text
            return False
    else:
        print 'Error :'+str(Respuesta.status_code)
        #print Respuesta.text
        return Respuesta.status_code
    """


def Mensajes(texto,tipo):
    Color ='red'
    top = Tk()
    top.geometry("+%d+%d" % (65,200))
    if tipo == 'OK':
        Color ='#00FF00'
        top.config(background=Color)
        top.title("OK")
    else:
        Color ='#FF0000'
        top.config(background=Color)
        top.title("Error")
    frame2 = Message(top, font='Arial', relief=RAISED, text = texto ,padx=50,pady=50,width=100, bg=Color)
    frame2.pack()

def Test_Nuevo_Servidor():
            N_Servidor = Nuevo_Servidor.get()
            N_Servidor = N_Servidor.strip()
            print '-----------------------------'
            print N_Servidor
            print '-----------------------------'
            #print 'hola'

            try:
                    socket.inet_aton(N_Servidor)
                    if N_Servidor.count('.') == 3:
                        print '---------------------------------'
                        print '1. Prueba de coneccion por IP'
                        print '---------------------------------'

                        print 'IP :' +str(N_Servidor)
                        Respuesta = Test_IP_Dom(N_Servidor, 'http')
                        #print Respuesta
                        #if Respuesta !='NO':
                        if Respuesta.find("Error") == -1:
                            Check_Res= Check_Respuestas(Respuesta)
                            if Check_Res == True:
                                print 'Esta IP es valida'
                                Mensajes('Test OK,Esta IP es valida se cambiara, pero el dominio sera el mismo.','OK')
                            else:
                                print 'Test Error,La IP no Funciona'
                                Mensajes('Test Error, '+ str(Check_Res)+' La IP no Funciona.','Error')
                        else:
                            print 'Test Error,La IP no contesto'
                            Mensajes('Test Error,La IP no contesto.','Error')



            except socket.error:
                    print '---------------------------------'
                    print 'NO es una IP revision por Dominio'
                    print '---------------------------------'
                    IP = Dominio_Valido(N_Servidor)
                    #print IP
                    if IP != False:
                            Test_IP_Dominio=0
                            print '---------------------------------'
                            print 'Prueba de coneccion por IP'
                            print '---------------------------------'

                            print 'IP :' +str(IP)
                            print 'Con http'

                            Respuesta= Test_IP_Dom(IP, 'http')
                            #print Respuesta
                            #if Respuesta !='NO':
                            if Respuesta.find("Error") == -1:
                                Check_Res= Check_Respuestas(Respuesta)

                                if Check_Res == True:
                                    print 'Esta IP es valida'
                                    Test_IP_Dominio=10
                                    #Mensajes('Test OK,Esta IP es valida se cambiara, pero el dominio sera el mismo.','OK')
                                else:
                                    print 'Test Error, '+ str(Check_Res)+' La IP no Funciona'
                                    #Mensajes('Test Error, '+ str(Check_Res)+' La IP no Funciona.','Error')
                            else:
                                print 'Test Error,La IP no contesto'


                            print 'Con https'

                            Respuesta= Test_IP_Dom(IP, 'https')
                            #print Respuesta
                            #if Respuesta !='NO':
                            if Respuesta.find("Error") == -1:
                                Check_Res= Check_Respuestas(Respuesta)

                                if Check_Res == True:
                                    print 'Esta IP es valida'
                                    Test_IP_Dominio=Test_IP_Dominio+100
                                    #Mensajes('Test OK,Esta IP es valida se cambiara, pero el dominio sera el mismo.','OK')
                                else:
                                    print 'Test Error, '+ str(Check_Res)+' La IP no Funciona'
                                    #Mensajes('Test Error, '+ str(Check_Res)+' La IP no Funciona.','Error')
                            else:
                                print 'Test Error,La IP no contesto'


                            print '---------------------------------'
                            print 'Prueba de coneccion por Dominio'
                            print '---------------------------------'

                            print 'Dominio :' +N_Servidor
                            print 'Con http'

                            Respuesta= Test_IP_Dom(N_Servidor, 'http')
                            #print Respuesta
                            if Respuesta !='NO':
                                Check_Res= Check_Respuestas(Respuesta)
                                if Check_Res == True:
                                    print 'Esta Dominio es valida'
                                    Test_IP_Dominio=Test_IP_Dominio+1
                                else:
                                    print 'Test Error, '+ str(Check_Res)+' La IP no Funciona'
                                    #Mensajes('Test Error, '+ str(Check_Res)+' La IP no Funciona.','Error')
                            else:
                                print 'Test Error,El dominio no contesto'

                            print 'Con https'

                            Respuesta= Test_IP_Dom(N_Servidor, 'https')
                            #print Respuesta
                            #if Respuesta !='NO':
                            if Respuesta.find("Error") == -1:
                                Check_Res= Check_Respuestas(Respuesta)
                                if Check_Res == True:
                                    print 'Esta Dominio es valida'
                                    Test_IP_Dominio=Test_IP_Dominio+1000
                                else:
                                    print 'Test Error, '+ str(Check_Res)+' La IP no Funciona'
                                    #Mensajes('Test Error, '+ str(Check_Res)+' La IP no Funciona.','Error')
                            else:
                                print 'Test Error,El dominio no contesto'


                            print Test_IP_Dominio

                            if Test_IP_Dominio == 0:    Mensajes('Test 0 Error, http Dominio NO, IP NO; https Dominio NO, IP NO.','Error')
                            if Test_IP_Dominio == 1:    Mensajes('Test 25%  OK, http Dominio OK, IP NO; https Dominio NO, IP NO.','OK')
                            if Test_IP_Dominio == 10:   Mensajes('Test 25%  OK, http Dominio NO, IP OK; https Dominio NO, IP NO.','OK')
                            if Test_IP_Dominio == 11:   Mensajes('Test 50%  OK, http Dominio OK, IP OK; https Dominio NO, IP NO.','OK')

                            if Test_IP_Dominio == 100:  Mensajes('Test 25%  OK, http Dominio NO, IP NO; https Dominio NO, IP OK.','OK')
                            if Test_IP_Dominio == 101:  Mensajes('Test 50%  OK, http Dominio OK, IP NO; https Dominio NO, IP OK.','OK')
                            if Test_IP_Dominio == 110:  Mensajes('Test 50%  OK, http Dominio NO, IP OK; https Dominio NO, IP OK.','OK')
                            if Test_IP_Dominio == 111:  Mensajes('Test 75%  OK, http Dominio OK, IP OK; https Dominio NO, IP OK.','OK')

                            if Test_IP_Dominio == 1000: Mensajes('Test 25%  OK, http Dominio NO, IP NO; https Dominio OK, IP NO.','OK')
                            if Test_IP_Dominio == 1001: Mensajes('Test 50%  OK, http Dominio OK, IP NO; https Dominio OK, IP NO.','OK')
                            if Test_IP_Dominio == 1010: Mensajes('Test 50%  OK, http Dominio NO, IP OK; https Dominio OK, IP NO.','OK')
                            if Test_IP_Dominio == 1011: Mensajes('Test 75%  OK, http Dominio OK, IP OK; https Dominio OK, IP NO.','OK')

                            if Test_IP_Dominio == 1100: Mensajes('Test 50%  OK, http Dominio NO, IP NO; https Dominio OK, IP OK.','OK')
                            if Test_IP_Dominio == 1101: Mensajes('Test 75%  OK, http Dominio OK, IP NO; https Dominio OK, IP OK.','OK')
                            if Test_IP_Dominio == 1110: Mensajes('Test 75%  OK, http Dominio NO, IP OK; https Dominio OK, IP OK.','OK')
                            if Test_IP_Dominio == 1111: Mensajes('Test 100% OK, http Dominio OK, IP OK; https Dominio OK, IP OK.','OK')


                    else:
                            print 'Dominio NO Valido, no hay IP asociada'
                            Mensajes('Dominio NO Valido, no hay IP asociada.','Error')


def Agregar_Nuevo_Servidor():

        print 'guardar en archivos'


        N_Servidor = Nuevo_Servidor.get()
        N_Servidor = N_Servidor.strip()
        print '-----------------------------'
        print N_Servidor
        print '-----------------------------'

        Variable_Dominio=''
        Variable_IP=''
        #print 'hola'

        try:
                socket.inet_aton(N_Servidor)
                if N_Servidor.count('.') == 3:
                    print '---------------------------------'
                    print '1. Prueba de coneccion por IP'
                    print '---------------------------------'

                    print 'IP :' +str(N_Servidor)
                    Respuesta = Test_IP_Dom(N_Servidor, 'http')
                    #print Respuesta
                    #if Respuesta !='NO':
                    if Respuesta.find("Error") == -1:
                        Check_Res= Check_Respuestas(Respuesta)
                        if Check_Res == True:
                            print 'Esta IP es valida'
                            Variable_IP=str(N_Servidor)

                            print Variable_IP
                            Borrar(32)
                            Escrivir_Archivo2(Variable_IP,32) #N_A_Dominio_Servidor
                            # commands.getoutput('sudo reboot')
                            #Mensajes('Test OK,Esta IP es valida se cambiara, pero el dominio sera el mismo.','OK')
                        else:
                            print 'Test Error,La IP no Funciona'
                            Mensajes('Test Error, '+ str(Check_Res)+' La IP no Funciona.','Error')
                    else:
                        print 'Test Error,La IP no contesto'
                        Mensajes('Test Error,La IP no contesto.','Error')



        except socket.error:
                print '---------------------------------'
                print 'NO es una IP revision por Dominio'
                print '---------------------------------'
                IP = Dominio_Valido(N_Servidor)
                Variable_Dominio = N_Servidor
                Variable_IP = str(IP)
                #print IP
                if IP != False:

                        Test_IP_Dominio=0
                        print '---------------------------------'
                        print 'Prueba de coneccion por IP'
                        print '---------------------------------'

                        print 'IP :' +str(IP)
                        print 'Con http'

                        Respuesta= Test_IP_Dom(IP, 'http')
                        #print Respuesta
                        #if Respuesta !='NO':
                        if Respuesta.find("Error") == -1:
                            Check_Res= Check_Respuestas(Respuesta)

                            if Check_Res == True:
                                print 'Esta IP es valida'
                                Test_IP_Dominio=10
                                #Variable_IP = str(Respuesta)
                                #Mensajes('Test OK,Esta IP es valida se cambiara, pero el dominio sera el mismo.','OK')
                            else:
                                print 'Test Error, '+ str(Check_Res)+' La IP no Funciona'
                                #Mensajes('Test Error, '+ str(Check_Res)+' La IP no Funciona.','Error')
                        else:
                            print 'Test Error,La IP no contesto'


                        print 'Con https'

                        Respuesta= Test_IP_Dom(IP, 'https')
                        #print Respuesta
                        #if Respuesta !='NO':
                        if Respuesta.find("Error") == -1:
                            Check_Res= Check_Respuestas(Respuesta)

                            if Check_Res == True:
                                print 'Esta IP es valida'
                                Test_IP_Dominio=Test_IP_Dominio+100
                                #Variable_IP = str(Respuesta)
                                #Mensajes('Test OK,Esta IP es valida se cambiara, pero el dominio sera el mismo.','OK')
                            else:
                                print 'Test Error, '+ str(Check_Res)+' La IP no Funciona'
                                #Mensajes('Test Error, '+ str(Check_Res)+' La IP no Funciona.','Error')
                        else:
                            print 'Test Error,La IP no contesto'


                        print '---------------------------------'
                        print 'Prueba de coneccion por Dominio'
                        print '---------------------------------'

                        print 'Dominio :' +N_Servidor
                        print 'Con http'

                        Respuesta= Test_IP_Dom(N_Servidor, 'http')
                        #print Respuesta
                        #if Respuesta !='NO':
                        if Respuesta.find("Error") == -1:
                            Check_Res= Check_Respuestas(Respuesta)
                            if Check_Res == True:
                                print 'Esta Dominio es valida'
                                Test_IP_Dominio=Test_IP_Dominio+1
                                #Variable_Dominio = N_Servidor
                            else:
                                print 'Test Error, '+ str(Check_Res)+' La IP no Funciona'
                                #Mensajes('Test Error, '+ str(Check_Res)+' La IP no Funciona.','Error')
                        else:
                            print 'Test Error,El dominio no contesto'

                        print 'Con https'

                        Respuesta= Test_IP_Dom(N_Servidor, 'https')
                        #print Respuesta
                        #if Respuesta !='NO':
                        if Respuesta.find("Error") == -1:

                            Check_Res= Check_Respuestas(Respuesta)
                            if Check_Res == True:
                                print 'Esta Dominio es valida'
                                Test_IP_Dominio=Test_IP_Dominio+1000
                                #Variable_Dominio = N_Servidor
                            else:
                                print 'Test Error, '+ str(Check_Res)+' La IP no Funciona'
                                #Mensajes('Test Error, '+ str(Check_Res)+' La IP no Funciona.','Error')
                        else:
                            print 'Test Error,El dominio no contesto'


                        print Test_IP_Dominio

                        if Test_IP_Dominio == 0:    Mensajes('Test 0 Error, http Dominio NO, IP NO; https Dominio NO, IP NO.','Error')
                        """
                        if Test_IP_Dominio == 1:    Mensajes('Test 25%  OK, http Dominio OK, IP NO; https Dominio NO, IP NO.','OK')
                        if Test_IP_Dominio == 10:   Mensajes('Test 25%  OK, http Dominio NO, IP OK; https Dominio NO, IP NO.','OK')
                        if Test_IP_Dominio == 11:   Mensajes('Test 50%  OK, http Dominio OK, IP OK; https Dominio NO, IP NO.','OK')

                        if Test_IP_Dominio == 100:  Mensajes('Test 25%  OK, http Dominio NO, IP NO; https Dominio NO, IP OK.','OK')
                        if Test_IP_Dominio == 101:  Mensajes('Test 50%  OK, http Dominio OK, IP NO; https Dominio NO, IP OK.','OK')
                        if Test_IP_Dominio == 110:  Mensajes('Test 50%  OK, http Dominio NO, IP OK; https Dominio NO, IP OK.','OK')
                        if Test_IP_Dominio == 111:  Mensajes('Test 75%  OK, http Dominio OK, IP OK; https Dominio NO, IP OK.','OK')

                        if Test_IP_Dominio == 1000: Mensajes('Test 25%  OK, http Dominio NO, IP NO; https Dominio OK, IP NO.','OK')
                        if Test_IP_Dominio == 1001: Mensajes('Test 50%  OK, http Dominio OK, IP NO; https Dominio OK, IP NO.','OK')
                        if Test_IP_Dominio == 1010: Mensajes('Test 50%  OK, http Dominio NO, IP OK; https Dominio OK, IP NO.','OK')
                        if Test_IP_Dominio == 1011: Mensajes('Test 75%  OK, http Dominio OK, IP OK; https Dominio OK, IP NO.','OK')

                        if Test_IP_Dominio == 1100: Mensajes('Test 50%  OK, http Dominio NO, IP NO; https Dominio OK, IP OK.','OK')
                        if Test_IP_Dominio == 1101: Mensajes('Test 75%  OK, http Dominio OK, IP NO; https Dominio OK, IP OK.','OK')
                        if Test_IP_Dominio == 1110: Mensajes('Test 75%  OK, http Dominio NO, IP OK; https Dominio OK, IP OK.','OK')
                        if Test_IP_Dominio == 1111: Mensajes('Test 100% OK, http Dominio OK, IP OK; https Dominio OK, IP OK.','OK')
                        """

                        if Test_IP_Dominio !=0:
                            print 'guardando y reiniciando'
                            print Test_IP_Dominio
                            print Variable_IP
                            print Variable_Dominio

                            #print Variable_IP
                            Borrar(32)
                            Escrivir_Archivo2(Variable_IP,32)#N_A_IP_Servidor
                            Borrar(31)
                            Escrivir_Archivo2(Variable_Dominio,31)#N_A_Dominio_Servidor
                            Borrar(36)
                            Escrivir_Archivo2(str(Test_IP_Dominio),36)#N_A_Dominio_Servidor

                            commands.getoutput('sudo reboot')

                else:
                        print 'Dominio NO Valido, no hay IP asociada'
                        Mensajes('Dominio NO Valido, no hay IP asociada.','Error')






def Torniquete():
        #Menu Principal
        No_ver_menu_principal()
        P_Menu.place(x=Ini_x+150, y=Ini_y+330)#P_Menu.place(x=Ini_x+(Disx*1)+25, y=Ini_y+(Disy*9))
        #Botones configuara torniquete
        P_C_Config_Torniquete.place(bordermode=OUTSIDE, height=20, width=150, y=10, x= 90)
        P_C_Salir_Izquierda.place(x=Ini_x+(Disx*0)+25, y=Ini_y+(Disy*0)-60)
        P_C_Salir_Derecha.place(x=Ini_x+(Disx*0)+25, y=Ini_y+(Disy*1)-10)
        P_C_Aceptar_Tor.place(x=Ini_x, y=Ini_y+330)
        P_C_CTiempo_Torniquete.place(bordermode=OUTSIDE, height=20, width=150, x= Ini_x+(Disx*1)-10, y= Ini_y+(Disy*3)-40)
        texto = StringVar()
        texto.set(str(Tiempo_Torniquete))
        P_C_Tiempo_Torniquete.config(textvariable=texto)

        P_C_Tiempo_Torniquete.place(bordermode=OUTSIDE, height=20, width=150, x= Ini_x+(Disx*1)-10, y= Ini_y+(Disy*4)-40)
        P_C_Tiempo_Torniquete_incremento.place(x=Ini_x+(Disx*2)+15, y=Ini_y+(Disy*4)-60)
        P_C_Tiempo_Torniquete_decremento.place(x=Ini_x+(Disx*0)+25, y=Ini_y+(Disy*4)-60)


        #Botones torniquete

def No_ver_Torniquete():

        #Botones Restablecer
        P_C_Config_Torniquete.place_forget()
        P_C_Salir_Izquierda.place_forget()
        P_C_Salir_Derecha.place_forget()
        P_C_Aceptar_Tor.place_forget()
        P_C_CTiempo_Torniquete.place_forget()
        P_C_Tiempo_Torniquete.place_forget()
        P_C_Tiempo_Torniquete_incremento.place_forget()
        P_C_Tiempo_Torniquete_decremento.place_forget()

def Tor_Derecha():
        Borrar(13)
        Escrivir_Estados('D',13) #
def Tor_Izquierda():
        Borrar(13)
        Escrivir_Estados('I',13) #

def Valores_Fabrica():
        print 'valores de Fabrica'
        Base_Datos_Local()
        Borrar_Historial ()
        #estados de sensores y lecturas
        #led
        Borrar(10)      #led
        Escrivir_Estados('0',10)
        Borrar(3)      #Estado led
        Escrivir_Estados('0',3)
        #tecla
        Borrar(4)      #Esatado teclado
        Borrar(5)      #Teclas
        #chicharra
        Borrar(6)      #Esatado chicharra
        Escrivir_Estados('1',6)
        #Qr
        Borrar(7)      #QR
        Borrar(8)      #Estado QR
        Borrar(9)      #Estado sensor
        Escrivir_Estados('0',9)
        Borrar(11)      #Estado QR repetido
        #Torniquete
        Borrar(13)      #Direcion Torniquete
        Escrivir_Estados('D',13)
        #Tiempo Torniquete
        Borrar(30)      #Esatado chicharra
        Escrivir_Estados('1',30)

        #Escrivir_Estados(Estados,3)


def Base_Datos_Local():

        Borrar(0)       #borrar tabla servidor
        Borrar(1)       #borrar tabla lector
        Borrar(2)       #borrar tabla Enviar
        print 'Base datos borrado'

def Borrar_Historial():

       Borrar(12)       #Borrar Numero de lecturas
       Escrivir('0',12) #dejar en 0 las lecturas

       Borrar(14)       #Borrar Numero de Reinicios
       Escrivir('0',14) #dejar en 0 los reinicios
       print 'Historial borrado'

def Aceptar_reboot():
        commands.getoutput('sudo reboot')



def Multi_Torniquete():
        #Menu Principal
        No_ver_menu_principal()
        P_Menu.place(x=Ini_x+150, y=Ini_y+330)
        #Botones configuara torniquete

        M_T_Title.place(bordermode=OUTSIDE, height=20, width=160, x=80, y=10)
        M_T_lista.place(bordermode=OUTSIDE, height=29, width=200, x=60, y=40)
        #M_T_List.place(bordermode=OUTSIDE, height=20, width=100, y=60)

        M_T_Borrar_IP.place(bordermode=OUTSIDE, height=40, width=200, x=60, y=80)
        M_T_IPs.place(bordermode=OUTSIDE, height=20, width=30,x=15, y=135)
        M_T_IP.place(bordermode=OUTSIDE, height=30, width=200, x=60, y=130)

        M_T_but1.place(x=MIni_xip+(MDisxip*0), y=MIni_y+(MDisyip*1))
        M_T_but2.place(x=MIni_xip+(MDisxip*1), y=MIni_y+(MDisyip*1))
        M_T_but3.place(x=MIni_xip+(MDisxip*2), y=MIni_y+(MDisyip*1))
        M_T_but4.place(x=MIni_xip+(MDisxip*0), y=MIni_y+(MDisyip*2))
        M_T_but5.place(x=MIni_xip+(MDisxip*1), y=MIni_y+(MDisyip*2))
        M_T_but6.place(x=MIni_xip+(MDisxip*2), y=MIni_y+(MDisyip*2))
        M_T_but7.place(x=MIni_xip+(MDisxip*0), y=MIni_y+(MDisyip*3))
        M_T_but8.place(x=MIni_xip+(MDisxip*1), y=MIni_y+(MDisyip*3))
        M_T_but9.place(x=MIni_xip+(MDisxip*2), y=MIni_y+(MDisyip*3))
        M_T_but0.place(x=MIni_xip+(MDisxip*0), y=MIni_y+(MDisyip*4))
        M_T_butb.place(x=MIni_xip+(MDisxip*1), y=MIni_y+(MDisyip*4))
        M_T_butp.place(x=MIni_xip+(MDisxip*2), y=MIni_y+(MDisyip*4))
        M_T_Aceptar_IP.place(x=MIni_xip, y=MDisyip+365)



def No_ver_Multi_Torniquete():

        #Botones Restablecer

        M_T_Title.place_forget()
        #M_T_List.place_forget()
        M_T_IPs.place_forget()
        M_T_IP.place_forget()
        M_T_lista.place_forget()

        M_T_Borrar_IP.place_forget()
        M_T_but1.place_forget()
        M_T_but2.place_forget()
        M_T_but3.place_forget()
        M_T_but4.place_forget()
        M_T_but5.place_forget()
        M_T_but6.place_forget()
        M_T_but7.place_forget()
        M_T_but8.place_forget()
        M_T_but9.place_forget()
        M_T_but0.place_forget()
        M_T_butb.place_forget()
        M_T_butp.place_forget()
        M_T_Aceptar_IP.place_forget()

def Eliminar_IP_Dispostivos():

        Ip_dispostivo = M_T_lista.get()
        print Ip_dispostivo

        if (len(Ip_dispostivo)==0):
                top = Tk()
                top.geometry("+%d+%d" % (65,200))
                top.config(background='Red')
                top.title("Error")
                frame2 = Message(top, font='Arial', relief=RAISED, text='No selecciono una IP.',padx=50,pady=50,width=100, bg='Red')
                frame2.pack()
        else:
                M_T_lista["values"]= []
                IPs = Leer_Archivo(21)
                redes =IPs.split("\n")
                #print len(redes)

                for x1 in redes:
                        if len(x1) >= 3:
                                if x1.find(Ip_dispostivo):
                                        values = list(M_T_lista["values"])
                                        M_T_lista["values"]= values+ [x1]

                Borrar(21)
                for x1 in M_T_lista["values"]:
                        #print x1
                        Escrivir(x1,21)

                #Escrivir(Ip_dispostivo,21)
                #Actualizar_lista2()
                M_T_lista.select_clear()



def Agregar_IP_Dispostivos():
        Ip_dispostivo=M_T_IP.get()
        print Ip_dispostivo

        if (len(Ip_dispostivo)==0):
                top = Tk()
                top.geometry("+%d+%d" % (65,200))
                top.config(background='Red')
                top.title("Error")
                frame2 = Message(top, font='Arial', relief=RAISED, text='El campo esdta vacio.',padx=50,pady=50,width=100, bg='Red')
                frame2.pack()
        else :
                print 'verificacion ip valida'

                if (check_IP(Ip_dispostivo) == False) :
                        top = Tk()
                        top.geometry("+%d+%d" % (65,200))
                        top.config(background='Red')
                        top.title("Error")
                        frame2 = Message(top, font='Arial', relief=RAISED, text='NO es una IP valida.',padx=50,pady=50,width=100, bg='Red')
                        frame2.pack()
                else:
                        Valido =0
                        for x1 in M_T_lista["values"]:
                                print x1
                                if len(x1) >= 3:
                                        if x1.find(Ip_dispostivo) != -1:
                                                Valido = 1
                                                #print 'existe'
                        if Valido == 1:
                                top = Tk()
                                top.geometry("+%d+%d" % (65,200))
                                top.config(background='Red')
                                top.title("Error")
                                frame2 = Message(top, font='Arial', relief=RAISED, text='Existe esta IP',padx=50,pady=50,width=100, bg='Red')
                                frame2.pack()
                        else:
                                Escrivir(Ip_dispostivo,21)
                                #Actualizar_lista2()
                                M_T_lista.select_clear()


def desplegar2(event):
        Actualizar_lista2()
        #print 'desplicada'
        return 0

def Actualizar_lista2():

        M_T_lista["values"]= []
        IPs = Leer_Archivo(21)
        redes =IPs.split("\n")


        for x1 in redes:

                values = list(M_T_lista["values"])
                M_T_lista["values"]= values+ [x1]

def desplegar_IP_Static(event):
        L_Ip_Static_lista["values"]= []

        L_Ip_Static_lista["values"]= ["Ethernet","WIFI"]



        return 0

#-----------------------------------
#-----          Definiciones    ----
#-----------------------------------

#----------------------------------------
#-----          Pagina Menu Inicio   ----
#----------------------------------------

L_Menu_Principal = Label(tk, font='Arial', bg='Dark gray', text="MENU PRINCIPAL")
P_wifi = Button(tk,padx=DX_b-54,pady=DY_b,bd=BD,command=V_wifi_Minusculas,text="Configurar Wifi",font=Fuente)
P_IP = Button(tk,padx=DX_b-75,pady=DY_b,bd=BD,command=V_IP,text="IP Estatica Ethernet",font=Fuente)
P_Restablecer = Button(tk,padx=DX_b-95,pady=DY_b,bd=BD,command=Restablecer,text="Restablacer Dispositivo",font=Fuente)
P_Confi_Torniquete = Button(tk,padx=DX_b-89,pady=DY_b,bd=BD,command=Torniquete,text="Configurar Torniquete",font=Fuente)
P_Confi_Multi_Dispositivo = Button(tk,padx=DX_b-62,pady=DY_b,bd=BD,command=Multi_Torniquete,text="Multi Torniquete",font=Fuente)
P_salir = Button(tk,padx=DX_b-5,pady=DY_b,bd=BD,command=salir,text="Salir",font=Fuente)

P_Menu = Button(tk,padx=DX-14,pady=DY-10,bd=BD,command=L_menu_inicio,text="Menu Inicio",font=Fuente)

ver_menu_principal()

#P_IP.place(x=Ini_x+(Disx*1)+25, y=Ini_y+(Disy*9))
#-------------------------------------------
#-----          Pagina Ip Static        ----
#-------------------------------------------
L_Ip_Static = Label(tk, font='Arial', bg='Dark gray', text="IP STATIC")
L_Ip_Static_lista = ttk.Combobox(tk, font=Fuente2, width=15,height=16, state="readonly")
L_Ip_Static_lista.bind("<Button-1>",desplegar_IP_Static)
L_Ip = Label(tk, font='Arial', bg='Dark gray', text="IP: ")
L_Gat = Label(tk, font='Arial', bg='Dark gray', text="Gateway: ")
IP=Entry(tk, font='Arial',textvar=textin)
Gateway=Entry(tk, font='Arial',textvar=textin2) # , show='*'se escoge encriptar con * la contraseña
but1=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('1'),text='1',font=Fuenteip)
but2=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('2'),text='2',font=Fuenteip)
but3=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('3'),text='3',font=Fuenteip)
but4=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('4'),text='4',font=Fuenteip)
but5=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('5'),text='5',font=Fuenteip)
but6=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('6'),text='6',font=Fuenteip)
but7=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('7'),text='7',font=Fuenteip)
but8=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('8'),text='8',font=Fuenteip)
but9=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('9'),text='9',font=Fuenteip)
but0=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('0'),text='0',font=Fuenteip)
butp=Button(tk,padx=DXip+4,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('.'),text='.',font=Fuenteip)
butb=Button(tk,padx=DXip-6,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('◄'),text='◄',font=Fuenteip)
Aceptar_IP = Button(tk,padx=DX,pady=DY-10,bd=BD,command=verificar_IP_Static,text="Aceptar",font=Fuente)
#Cancelar_IP = Button(tk,padx=DX,pady=DY,bd=BD,command=salir,text="Cancelar",font=Fuente)


#-------------------------------------------
#-----          Pagina Wifi             ----
#-------------------------------------------




L_wifi = Label(tk, font='Arial', bg='Dark gray', text="WIFI")
L_password = Label(tk, font='Arial', bg='Dark gray', text="Password")

lista = ttk.Combobox(tk, font=Fuente2, width=15,height=16, state="readonly")
#lista.Combobox(tk, postcomand=desplagar)
lista.bind("<Button-1>",desplegar)

wifi=Entry(tk, font='Arial',textvar=textin3)
contrasena=Entry(tk, font='Arial',textvar=textin4) # , show='*'se escoge encriptar con * la contraseña
Aceptar_W = Button(tk,padx=DX,pady=DY-10,bd=BD,command=verificar_wifi,text="Aceptar",font=Fuente)

butqw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('q'),text='q',font=Fuentew)
butww=Button(tk,padx=DXw-1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('w'),text='w',font=Fuentew)
butew=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('e'),text='e',font=Fuentew)
butrw=Button(tk,padx=DXw+3,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('r'),text='r',font=Fuentew)
buttw=Button(tk,padx=DXw+4,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('t'),text='t',font=Fuentew)
butyw=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('y'),text='y',font=Fuentew)
butuw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('u'),text='u',font=Fuentew)
butiw=Button(tk,padx=DXw+4,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('i'),text='i',font=Fuentew)
butow=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('o'),text='o',font=Fuentew)
butpw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('p'),text='p',font=Fuentew)
butaw=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('a'),text='a',font=Fuentew)
butsw=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('s'),text='s',font=Fuentew)
butdw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('d'),text='d',font=Fuentew)
butfw=Button(tk,padx=DXw+4,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('f'),text='f',font=Fuentew)
butgw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('g'),text='g',font=Fuentew)
buthw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('h'),text='h',font=Fuentew)
butjw=Button(tk,padx=DXw+4,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('j'),text='j',font=Fuentew)
butkw=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('k'),text='k',font=Fuentew)
butlw=Button(tk,padx=DXw+5,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('l'),text='l',font=Fuentew)
butzw=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('z'),text='z',font=Fuentew)
butxw=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('x'),text='x',font=Fuentew)
butcw=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('c'),text='c',font=Fuentew)
butvw=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('v'),text='v',font=Fuentew)
butbw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('b'),text='b',font=Fuentew)
butnw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('n'),text='n',font=Fuentew)
butmw=Button(tk,padx=DXw-4,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('m'),text='m',font=Fuentew)
butespw=Button(tk,padx=DXw+68,pady=DYw,bd=BD,bg='white',command=lambda:clickbut(' '),text=' ',font=Fuentew)



butMYw=Button(tk,padx=DXw-4,pady=DYw,bd=BD,bg='white',command=V_wifi_May_Minu,text='▲',font=Fuentew)
but123w=Button(tk,padx=DXw+9,pady=DYw,bd=BD,bg='white',command=V_wifi_Numeros,text='123?',font=Fuentew)
butabcw=Button(tk,padx=DXw+17,pady=DYw,bd=BD,bg='white',command=V_wifi_Minusculas,text='ABC',font=Fuentew)
#butbw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('b'),text='b',font=Fuente)
butBow=Button(tk,padx=DXw-4,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('◄'),text='◄',font=Fuentew)
#◄ ▲ ► ▼


butQw=Button(tk,padx=DXw-1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('Q'),text='Q',font=Fuentew)
butWw=Button(tk,padx=DXw-2,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('W'),text='W',font=Fuentew)
butEw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('E'),text='E',font=Fuentew)
butRw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('R'),text='R',font=Fuentew)
butTw=Button(tk,padx=DXw-1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('T'),text='T',font=Fuentew)
butYw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('Y'),text='Y',font=Fuentew)
butUw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('U'),text='U',font=Fuentew)
butIw=Button(tk,padx=DXw+4,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('I'),text='I',font=Fuentew)
butOw=Button(tk,padx=DXw-1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('O'),text='O',font=Fuentew)
butPw=Button(tk,padx=DXw-1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('P'),text='P',font=Fuentew)
butAw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('A'),text='A',font=Fuentew)
butSw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('S'),text='S',font=Fuentew)
butDw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('D'),text='D',font=Fuentew)
butFw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('F'),text='F',font=Fuentew)
butGw=Button(tk,padx=DXw-2,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('G'),text='G',font=Fuentew)
butHw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('H'),text='H',font=Fuentew)
butJw=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('J'),text='J',font=Fuentew)
butKw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('K'),text='K',font=Fuentew)
butLw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('L'),text='L',font=Fuentew)
butZw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('Z'),text='Z',font=Fuentew)
butXw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('X'),text='X',font=Fuentew)
butCw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('C'),text='C',font=Fuentew)
butVw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('V'),text='V',font=Fuentew)
butBw=Button(tk,padx=DXw-1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('B'),text='B',font=Fuentew)
butNw=Button(tk,padx=DXw-1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('N'),text='N',font=Fuentew)
butMw=Button(tk,padx=DXw-2,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('M'),text='M',font=Fuentew)


but1w=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('1'),text='1',font=Fuentew)
but2w=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('2'),text='2',font=Fuentew)
but3w=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('3'),text='3',font=Fuentew)
but4w=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('4'),text='4',font=Fuentew)
but5w=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('5'),text='5',font=Fuentew)
but6w=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('6'),text='6',font=Fuentew)
but7w=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('7'),text='7',font=Fuentew)
but8w=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('8'),text='8',font=Fuentew)
but9w=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('9'),text='9',font=Fuentew)
but0w=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('0'),text='0',font=Fuentew)

butA1w=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('#'),text='#',font=Fuentew)
butS2w=Button(tk,padx=DXw-2,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('&'),text='&',font=Fuentew)
butD3w=Button(tk,padx=DXw+3,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('/'),text='/',font=Fuentew)
butF4w=Button(tk,padx=DXw+2,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('-'),text='-',font=Fuentew)
butG5w=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('_'),text='_',font=Fuentew)
butH6w=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('+'),text='+',font=Fuentew)
butJ7w=Button(tk,padx=DXw+2,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('('),text='(',font=Fuentew)
butK8w=Button(tk,padx=DXw+3,pady=DYw,bd=BD,bg='white',command=lambda:clickbut(')'),text=')',font=Fuentew)
butL9w=Button(tk,padx=DXw+2,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('*'),text='*',font=Fuentew)
butZ0w=Button(tk,padx=DXw+3,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('.'),text='.',font=Fuentew)
butX1w=Button(tk,padx=DXw+3,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('!'),text='!',font=Fuentew)
butC2w=Button(tk,padx=DXw-1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('?'),text='?',font=Fuentew)
butV3w=Button(tk,padx=DXw-3,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('@'),text='@',font=Fuentew)
butB4w=Button(tk,padx=DXw+2,pady=DYw,bd=BD,bg='white',command=lambda:clickbut(':'),text=':',font=Fuentew)
butN5w=Button(tk,padx=DXw+2,pady=DYw,bd=BD,bg='white',command=lambda:clickbut(';'),text=';',font=Fuentew)
#butMw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('M'),text='M',font=Fuente)

#but0=Button(tk,padx=DX,pady=DY,bd=BD,bg='white',command=lambda:clickbut('0'),text='0',font=Fuente)
#butp=Button(tk,padx=DX+3,pady=DY,bd=BD,bg='white',command=lambda:clickbut('.'),text='.',font=Fuente)
#Aceptar_IP = Button(tk,padx=DX+5,pady=DY,bd=BD,command=verificar,text="Aceptar",font=Fuente)
#Cancelar_IP = Button(tk,padx=DX,pady=DY,bd=BD,command=salir,text="Cancelar",font=Fuente)


#-------------------------------------------
#-----          Pagina Restablecer      ----
#-------------------------------------------
P_R_Restablecer = Label(tk, font='Arial', bg='Dark gray', text="RESTABLECER")
P_R_Valores_Fabrica = Button(tk,padx=DX_b-65,pady=DY_b,bd=BD,command=Valores_Fabrica,text="Valores de Fabrica",font=Fuente)
P_R_Borrar_Bace_Datos = Button(tk,padx=DX_b-70,pady=DY_b,bd=BD,command=Base_Datos_Local,text="Base de datos local",font=Fuente)
P_R_Borrar_Historial = Button(tk,padx=DX_b-50,pady=DY_b,bd=BD,command=Borrar_Historial,text="Borrar Historial",font=Fuente)
P_R_Nuevo_Servidor = Button(tk,padx=DX_b-50,pady=DY_b,bd=BD,command=Ver_Nuevo_Servidor,text="Nuevo Servidor",font=Fuente)
P_R_Aceptar_Res = Button(tk,padx=DX,pady=DY-10,bd=BD,command=Aceptar_reboot,text="Aceptar",font=Fuente)

#-------------------------------------------
#-----          Pagina Configuracion torniquete      ----
#-------------------------------------------
P_C_Config_Torniquete = Label(tk, font='Arial', bg='Dark gray', text="Configurar Torniquete")
P_C_Salir_Izquierda = Button(tk,padx=DX_b-70,pady=DY_b,bd=BD,command=Tor_Izquierda,text="Salir por la Izquierda",font=Fuente)
P_C_Salir_Derecha = Button(tk,padx=DX_b-66,pady=DY_b,bd=BD,command=Tor_Derecha,text="Salir por la Derecha",font=Fuente)
P_C_Aceptar_Tor = Button(tk,padx=DX,pady=DY-10,bd=BD,command=Aceptar_reboot,text="Aceptar",font=Fuente)
P_C_CTiempo_Torniquete = Label(tk, font='Arial', bg='Dark gray', text="Tiempo Relevador")
P_C_Tiempo_Torniquete = Label(tk, font=Fuenteip, bg='Dark gray', text="1")
P_C_Tiempo_Torniquete_incremento=Button(tk,padx=DX-6,pady=DY,bd=BD,bg='white',command=lambda:clickbut_Tiempo('►'),text='►',font=Fuenteip)
P_C_Tiempo_Torniquete_decremento=Button(tk,padx=DX-6,pady=DY,bd=BD,bg='white',command=lambda:clickbut_Tiempo('◄'),text='◄',font=Fuenteip)

#R_but0=Button(tk,padx=DX,pady=DY,bd=BD,bg='white',command=lambda:clickbut('0'),text='0',font=Fuente)
#R_butp=Button(tk,padx=DX+3,pady=DY,bd=BD,bg='white',command=lambda:clickbut('.'),text='.',font=Fuente)


#-------------------------------------------
#-----          Pagina Multi Tornique       ----
#-------------------------------------------

M_T_Title = Label(tk, font='Arial', bg='Dark gray', text="IP, Torniquetes")
#M_T_List = Label(tk, font='Arial', bg='Dark gray', text="Listado")
M_T_IPs = Label(tk, font='Arial', bg='Dark gray', text="IP:")
M_T_lista = ttk.Combobox(tk, font=Fuente2, width=15,height=16, state="readonly")
M_T_lista.bind("<Button-1>",desplegar2)

M_T_IP=Entry(tk, font='Arial',textvar=textin5)

M_T_Borrar_IP = Button(tk,padx=DX,pady=DY-10,bd=BD,command=Eliminar_IP_Dispostivos,text="Eliminar IP",font=Fuente)
M_T_but1=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('1'),text='1',font=Fuenteip)
M_T_but2=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('2'),text='2',font=Fuenteip)
M_T_but3=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('3'),text='3',font=Fuenteip)
M_T_but4=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('4'),text='4',font=Fuenteip)
M_T_but5=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('5'),text='5',font=Fuenteip)
M_T_but6=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('6'),text='6',font=Fuenteip)
M_T_but7=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('7'),text='7',font=Fuenteip)
M_T_but8=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('8'),text='8',font=Fuenteip)
M_T_but9=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('9'),text='9',font=Fuenteip)
M_T_but0=Button(tk,padx=DXip,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('0'),text='0',font=Fuenteip)
M_T_butp=Button(tk,padx=DXip+4,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('.'),text='.',font=Fuenteip)
M_T_butb=Button(tk,padx=DXip-6,pady=DYip,bd=BD,bg='white',command=lambda:clickbut('◄'),text='◄',font=Fuenteip)

M_T_Aceptar_IP = Button(tk,padx=DX,pady=DY-10,bd=BD,command=Agregar_IP_Dispostivos,text="Agregar",font=Fuente)

#Cancelar_IP = Button(tk,padx=DX,pady=DY,bd=BD,command=salir,text="Cancelar",font=Fuente)
#Modificar_Archivo1(1,0)
#while 1:
#        a=0



#-------------------------------------------
#-----          Pagina Servidor         ----
#-------------------------------------------


L_Nuevo_Servidor = Label(tk, font='Arial', bg='Dark gray', text="Dominio:")
#L_password = Label(tk, font='Arial', bg='Dark gray', text="Password")

#lista = ttk.Combobox(tk, font=Fuente2, width=15,height=16, state="readonly")

#lista.bind("<Button-1>",desplegar)

Nuevo_Servidor=Entry(tk, font='Arial',textvar=textin6)#Entry(tk, font='Arial',textvar=textin3)
#contrasena=Entry(tk, font='Arial',textvar=textin4) # , show='*'se escoge encriptar con * la contraseña
Aceptar_Nuevo_Servidor = Button(tk,padx=DX,pady=DY-10,bd=BD,command=Agregar_Nuevo_Servidor,text="Aceptar",font=Fuente)
Test_Nuevo_Servidor = Button(tk,padx=DX,pady=DY-10,bd=BD,command=Test_Nuevo_Servidor,text="TEST",font=Fuente)

butqS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('q'),text='q',font=Fuentew)
butwS=Button(tk,padx=DXw-1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('w'),text='w',font=Fuentew)
buteS=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('e'),text='e',font=Fuentew)
butrS=Button(tk,padx=DXw+3,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('r'),text='r',font=Fuentew)
buttS=Button(tk,padx=DXw+4,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('t'),text='t',font=Fuentew)
butyS=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('y'),text='y',font=Fuentew)
butuS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('u'),text='u',font=Fuentew)
butiS=Button(tk,padx=DXw+4,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('i'),text='i',font=Fuentew)
butoS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('o'),text='o',font=Fuentew)
butpS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('p'),text='p',font=Fuentew)
butaS=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('a'),text='a',font=Fuentew)
butsS=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('s'),text='s',font=Fuentew)
butdS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('d'),text='d',font=Fuentew)
butfS=Button(tk,padx=DXw+4,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('f'),text='f',font=Fuentew)
butgS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('g'),text='g',font=Fuentew)
buthS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('h'),text='h',font=Fuentew)
butjS=Button(tk,padx=DXw+4,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('j'),text='j',font=Fuentew)
butkS=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('k'),text='k',font=Fuentew)
butlS=Button(tk,padx=DXw+5,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('l'),text='l',font=Fuentew)
butzS=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('z'),text='z',font=Fuentew)
butxS=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('x'),text='x',font=Fuentew)
butcS=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('c'),text='c',font=Fuentew)
butvS=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('v'),text='v',font=Fuentew)
butbS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('b'),text='b',font=Fuentew)
butnS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('n'),text='n',font=Fuentew)
butmS=Button(tk,padx=DXw-4,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('m'),text='m',font=Fuentew)
butespS=Button(tk,padx=DXw+68,pady=DYw,bd=BD,bg='white',command=lambda:clickbut(' '),text=' ',font=Fuentew)



butMYS=Button(tk,padx=DXw-4,pady=DYw,bd=BD,bg='white',command=V_Nuevo_Servidor_May_Minu,text='▲',font=Fuentew)
but123S=Button(tk,padx=DXw+9,pady=DYw,bd=BD,bg='white',command=V_Nuevo_Servidor_Numeros,text='123?',font=Fuentew)
butabcS=Button(tk,padx=DXw+17,pady=DYw,bd=BD,bg='white',command=V_Nuevo_Servidor_Minusculas,text='ABC',font=Fuentew)
#butbw=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('b'),text='b',font=Fuente)
butBoS=Button(tk,padx=DXw-4,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('◄'),text='◄',font=Fuentew)
#◄ ▲ ► ▼


butQS=Button(tk,padx=DXw-1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('Q'),text='Q',font=Fuentew)
butWS=Button(tk,padx=DXw-2,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('W'),text='W',font=Fuentew)
butES=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('E'),text='E',font=Fuentew)
butRS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('R'),text='R',font=Fuentew)
butTS=Button(tk,padx=DXw-1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('T'),text='T',font=Fuentew)
butYS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('Y'),text='Y',font=Fuentew)
butUS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('U'),text='U',font=Fuentew)
butIS=Button(tk,padx=DXw+4,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('I'),text='I',font=Fuentew)
butOS=Button(tk,padx=DXw-1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('O'),text='O',font=Fuentew)
butPS=Button(tk,padx=DXw-1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('P'),text='P',font=Fuentew)
butAS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('A'),text='A',font=Fuentew)
butSS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('S'),text='S',font=Fuentew)
butDS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('D'),text='D',font=Fuentew)
butFS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('F'),text='F',font=Fuentew)
butGS=Button(tk,padx=DXw-2,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('G'),text='G',font=Fuentew)
butHS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('H'),text='H',font=Fuentew)
butJS=Button(tk,padx=DXw+1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('J'),text='J',font=Fuentew)
butKS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('K'),text='K',font=Fuentew)
butLS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('L'),text='L',font=Fuentew)
butZS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('Z'),text='Z',font=Fuentew)
butXS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('X'),text='X',font=Fuentew)
butCS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('C'),text='C',font=Fuentew)
butVS=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('V'),text='V',font=Fuentew)
butBS=Button(tk,padx=DXw-1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('B'),text='B',font=Fuentew)
butNS=Button(tk,padx=DXw-1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('N'),text='N',font=Fuentew)
butMS=Button(tk,padx=DXw-2,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('M'),text='M',font=Fuentew)


but1S=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('1'),text='1',font=Fuentew)
but2S=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('2'),text='2',font=Fuentew)
but3S=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('3'),text='3',font=Fuentew)
but4S=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('4'),text='4',font=Fuentew)
but5S=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('5'),text='5',font=Fuentew)
but6S=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('6'),text='6',font=Fuentew)
but7S=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('7'),text='7',font=Fuentew)
but8S=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('8'),text='8',font=Fuentew)
but9S=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('9'),text='9',font=Fuentew)
but0S=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('0'),text='0',font=Fuentew)

butA1S=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('#'),text='#',font=Fuentew)
butS2S=Button(tk,padx=DXw-2,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('&'),text='&',font=Fuentew)
butD3S=Button(tk,padx=DXw+3,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('/'),text='/',font=Fuentew)
butF4S=Button(tk,padx=DXw+2,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('-'),text='-',font=Fuentew)
butG5S=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('_'),text='_',font=Fuentew)
butH6S=Button(tk,padx=DXw,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('+'),text='+',font=Fuentew)
butJ7S=Button(tk,padx=DXw+2,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('('),text='(',font=Fuentew)
butK8S=Button(tk,padx=DXw+3,pady=DYw,bd=BD,bg='white',command=lambda:clickbut(')'),text=')',font=Fuentew)
butL9S=Button(tk,padx=DXw+2,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('*'),text='*',font=Fuentew)
butZ0S=Button(tk,padx=DXw+3,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('.'),text='.',font=Fuentew)
butX1S=Button(tk,padx=DXw+3,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('!'),text='!',font=Fuentew)
butC2S=Button(tk,padx=DXw-1,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('?'),text='?',font=Fuentew)
butV3S=Button(tk,padx=DXw-3,pady=DYw,bd=BD,bg='white',command=lambda:clickbut('@'),text='@',font=Fuentew)
butB4S=Button(tk,padx=DXw+2,pady=DYw,bd=BD,bg='white',command=lambda:clickbut(':'),text=':',font=Fuentew)
butN5S=Button(tk,padx=DXw+2,pady=DYw,bd=BD,bg='white',command=lambda:clickbut(';'),text=';',font=Fuentew)





#-----------------------------------
#-----  Bucle principal         ----
#-----------------------------------
tk.mainloop()
