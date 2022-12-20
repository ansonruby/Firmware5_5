import urllib2 #librerio para control web
import os
import requests
import commands
import Control_Archivos2  as Ca


Generar		         = Ca.Generar_ID_Tarjeta

#local prueba equipo 
CE_V=0   # 0: servidor de prueba 1: las direciones del aplicativo
CE_url = "http:+++++++"

#------------------------------------------------
#               constantes del aplicativo
#------------------------------------------------

IP_servidorP    = 'http://35.161.178.60'                # Pruebas
IP_servidor     = 'http://34.210.5.192'                 # Servidor
#ID_Tarjeta      = 'AABA01092019b827eb08200a000001'
MAC_DIRC        = 'cat /sys/class/net/eth0/address'
MAC_DIRC        = 'cat /sys/class/net/wlan0/address'
MAC             = commands.getoutput(MAC_DIRC)
MAC             = MAC.replace(":","")
ID_Tarjeta      = Generar(MAC)                             # ID
ID_Tarjeta      = '23'  #'19' #ID de prueba 

#------		Directorio
CE_rl =[        "/api/access/keyboard_access",      # Enviar Teclado
                "/api/access/grant",                # Enviar QR
                "/api/access/get_granted_users_pi", # Resivir usuarios
                "/api/access/set_in_out_activity",  # Enviar E/S sin Internet
                "/api/access/verify_conection",     # Verificar conexion
                "/api/firmware/review_update",      # Peticion Actualizacion
                "/api/firmware/confirm_update"      # Confirmacion Actualizacion
        ]

#print ID_Tarjeta
def Confimacion_Firmware(T_actual, vercion_Actual_Firmware,LOG):
    global CE_url
    global CE_url_Teclado
    global CE_rl
    global CE_rlP
    global ID_Tarjeta
        
    CE_peticion='NO'
    CE_cabeceras = {
        "Content-Type" : "application/json",
        "Fuseaccess-Id" : ID_Tarjeta,
        "Time-Scan" : T_actual
    }
    
    #CE_url = "http://35.161.178.60/api/firmware/confirm_update"
    
    if CE_V != 0	: CE_url = IP_servidor+CE_rl[6]         #CE_rl[4]
    else		: CE_url = IP_servidorP+CE_rl[6]        #CE_rlP[4]
    
    #print CE_url
    
    
    if len(LOG)>=2:
        CE_datos ='{"version":"'+vercion_Actual_Firmware+'","update":"0","log":"'+LOG+'"}' 
    else :
        CE_datos ='{"version":"'+vercion_Actual_Firmware+'","update":"1"}' 
    print CE_datos
    #CE_datos ='{"version":"2019.12.3.0","update":"1"}'#Formato actualisacion correcta
    #CE_datos ='{"version":"2019.12.3.0","update":"0","log":"2.3 herror ...."}' #Formato herror
		
    try:
        CE_peticion = requests.post(CE_url, data=CE_datos, headers=CE_cabeceras, timeout=2)
        return CE_peticion
    except:
        return CE_peticion


def Veri_Firmware(T_actual, vercion_Actual_Firmware):
    global CE_url
    global CE_url_Teclado
    global CE_rl
    global CE_rlP
    global ID_Tarjeta
        
    CE_peticion='NO'
    CE_cabeceras = {
        "Content-Type" : "application/json",
        "Fuseaccess-Id" : ID_Tarjeta,
        "Time-Scan" : T_actual
    }
    
    #CE_url = "http://35.161.178.60/api/firmware/review_update"
    
    if CE_V != 0	: CE_url = IP_servidor+CE_rl[5]         #CE_rl[4]
    else		: CE_url = IP_servidorP+CE_rl[5]        #CE_rlP[4]
    
    #print CE_url
    
    CE_datos ='{"data":"'+vercion_Actual_Firmware+'"}'#ya con la vercion del dispsotivo
    print CE_datos
    #CE_datos ='{"data":"2019.12.3.0"}' #firmware actual
    #CE_datos ='{"data":"2020.2.10.0"}' # firmware a actualizar
		
    try:
        CE_peticion = requests.get(CE_url, data=CE_datos, headers=CE_cabeceras, timeout=2)
        return CE_peticion
    except:
        return CE_peticion
    
    """
    global CE_url
    
    CE_url = 'http://192.168.0.4/Actualizar/'
    
    CE_peticion='NO'
    
    try:
        CE_peticion = requests.get(CE_url, timeout=3)
        return CE_peticion.text
    except:
        return CE_peticion
    """




def ping ():
        
        global CE_url
        global IP_servidorP
        global IP_servidor

        CE_peticion='NO'

        if CE_V != 0	: CE_url = IP_servidor+CE_rl[4]         #CE_rl[4]
        else		: CE_url = IP_servidorP+CE_rl[4]        #CE_rlP[4]
	
        try:
                CE_peticion = requests.get(CE_url, timeout=1)
                return CE_peticion.text
        except:
                return CE_peticion


        
def envio(dat,T_actual,QR_Te):

        global CE_url
        global CE_url_Teclado
        global CE_rl
        global CE_rlP
        global ID_Tarjeta
        
        CE_peticion='NO'
        CE_cabeceras = {
        "Content-Type" : "application/json",
        "Fuseaccess-Id" : ID_Tarjeta,
        "Time-Scan" : T_actual
        }

        if CE_V != 0	: CE_url = IP_servidor+CE_rl[QR_Te]         #CE_rl[4]
        else		: CE_url = IP_servidorP+CE_rl[QR_Te]        #CE_rlP[4]
	
        if QR_Te == 0: # enviar lo digitado
                CE_datos ='{"rut":"'+dat+'"}'	#'{"rut":"99158441"}' 
        if QR_Te == 1:
                CE_datos ='{"data":"'+dat+'"}'	#'{"data":"99158441"}' 
        if QR_Te == 3:
                CE_datos = dat					# datos leidos para enviar
		
        try:
                CE_peticion = requests.post(CE_url, data=CE_datos, headers=CE_cabeceras, timeout=2)
                return CE_peticion
        except:
                return CE_peticion	

def Usuarios_Activos(T_actual):
        
        global ID_Tarjeta
        
        CE_peticion='NO'
        CE_cabeceras = {
        "Content-Type" : "application/json",
        "Fuseaccess-Id" : ID_Tarjeta,
        "Time-Scan" : T_actual
        }

        if CE_V != 0	: CE_url = IP_servidor+CE_rl[2]         #CE_rl[4]
        else		: CE_url = IP_servidorP+CE_rl[2]        #CE_rlP[4]
		
        try:
                CE_peticion = requests.get(CE_url, headers=CE_cabeceras, timeout=2)
                return CE_peticion
        except:
                return CE_peticion	
