#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Libreria persona , por el momento para revisar el estado de conecion interna  del dispotivo.











"""
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------

#---------------------------------------------------------------------------------------
#                                   importar complementos
#---------------------------------------------------------------------------------------

import socket
import urllib2
import os
import commands
import requests
import time


#-------------------------------------------------------
#                                   CONTANTES
#-------------------------------------------------------

#-------------------------------------------------------
#----      Estados de coneccion (wifi, ethernet)     ----
#-------------------------------------------------------
def Estatus_Coneccion (c):
        res2 = commands.getoutput('cat /sys/class/net/'+c+'/carrier')
        if res2 == '0':     return 0 #  print 'Desconectado'
        else:               return 1 # print 'Conectado'

#-----------------------------------------------------------
def GET_STatus_Red():
        Sres = ""
        Cantidad =0
        res = commands.getoutput('ls /sys/class/net/')
        redes =res.split("\n")

        for x1 in range(len(redes)):
                c= redes[x1]
                #print c
                if c.find('eth') != -1: #print 'ethernet'
                        if Estatus_Coneccion (c) == 0:  #print 'ED'
                            Sres = Sres + 'ED'
                            Cantidad+=1
                        else:                           #print 'EC'
                            Sres = Sres + 'EC'
                            Cantidad+=1
                if c.find('wlan') != -1: #print 'Wifi'

                        if Estatus_Coneccion (c) == 0:  #print 'WD'
                                Sres = Sres + 'WD'
                                Cantidad+=1
                        else:                           #print 'WC'
                                Sres = Sres + 'WC'
                                Cantidad+=1
        #print str(Cantidad) + Sres
        return  str(Cantidad) + Sres

#-----------------------------------------------------------
def Status_Redes():
	Estado_redes = GET_STatus_Red()
	if Estado_redes.find('C') != -1: 	return 1 #print 'hay red lan'
	else : 								return 0 #print 'No LAN'

#-----------------------------------------------------------
def Get_MAC_addres():
    MAC_DIRC        = 'cat /sys/class/net/wlan0/address'
    MAC             = commands.getoutput(MAC_DIRC)
    MAC             = MAC.replace(":","")
    return  MAC

#----      verificar Ip o Dominio valido (wifi, ethernet)     ----
#-----------------------------------------------------------
def Validar_IP(IP):
    try:
        socket.inet_aton(IP)
        if IP.count('.') == 3:
            return True
        else:
            return False
    except socket.error:
        return False
#-----------------------------------------------------------
def Validar_Dominio(Dominio):
    Resolver = "host -t A  " + Dominio + "   | grep address | awk {'print $4'}"    
    address = commands.getoutput(Resolver)
    try:
        if Validar_IP(address):
            return address
        else:
            return False
    except socket.error:
        return False

#-----------------------------------------------------------
#               Pruebas de funcioanmiento
#-----------------------------------------------------------


#-----------------------------------------------------------
#-----------------------------------------------------------
#                       RESUMEN y descripciones
#-----------------------------------------------------------
#-----------------------------------------------------------
