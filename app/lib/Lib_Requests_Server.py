
#-------------------------------------------------------
#----      importar complementos                    ----
#-------------------------------------------------------
#---pendientes no se utilizan
import socket
import urllib2
import os
import commands
import requests
import time

#-------------------------------------------------------
#                                   CONTANTES
#-------------------------------------------------------

CE_V = 1          # 0: servidor de prueba 1: las direciones del aplicativo
P_Mensajes=1     # 0: NO print  1: Print


L_R_app =[      "/api/access/keyboard_access",      # Enviar Teclado
                "/api/access/grant",                # Enviar QR
                "/api/access/get_granted_users_pi", # Resivir usuarios
                "/api/access/set_in_out_activity",  # Enviar E/S sin Internet
                "/api/access/verify_conection",     # Verificar conexion
                "/api/firmware/review_update",      # Peticion Actualizacion
                "/api/firmware/confirm_update"      # Confirmacion Actualizacion
        ]


L_R_pru =[      "/api/access/keyboard_access/index.php",      # Enviar Teclado
                "/api/access/grant/index.php",                # Enviar QR
                "/api/access/get_granted_users_pi/index.php", # Resivir usuarios
                "/api/access/set_in_out_activity/index.php",  # Enviar E/S sin Internet
                "/api/access/verify_conection/index.php",     # Verificar conexion
                "/api/firmware/review_update/index.php",      # Peticion Actualizacion
                "/api/firmware/confirm_update/index.php"      # Confirmacion Actualizacion
        ]

if CE_V == 1:   CE_rl = L_R_app
else:           CE_rl = L_R_pru

#-------------------------------------------------------
#----      Funciones para peticiones al servidor     ----
#-------------------------------------------------------
def Get_Post_try_catch(peticion, CE_url, CE_datos, CE_cabeceras, tout):
    try:
        if peticion == 'GET' : CE_peticion = requests.get(CE_url, data=CE_datos, headers=CE_cabeceras, timeout=tout)
        if peticion == 'POST': CE_peticion = requests.post(CE_url, data=CE_datos, headers=CE_cabeceras, timeout=tout)
        if peticion == 'GET_SIN_PARAMETROS': CE_peticion = requests.get(CE_url, timeout=tout)
        if peticion == 'GET_SOLO_CABECERA': CE_peticion = requests.get(CE_url, headers=CE_cabeceras, timeout=tout)
        #print CE_peticion
        if CE_peticion.status_code == 200:
            Texto = CE_peticion.text
            if Texto.find("Access denied") == -1:
                if P_Mensajes:
                    print '200 :'+ CE_peticion.text
                return CE_peticion.text
            else:
                if P_Mensajes:
                    print '200 : Access denied'
                return 'Error :Access denied'

        else :
            if P_Mensajes:
                print 'Error :'+str(CE_peticion.status_code)
                print CE_peticion.text
            return 'Error :'+str(CE_peticion.status_code)

    #except requests.ConnectionError, e:
    except :
        #print e
        if P_Mensajes:
            print  'Error :Conection'
        return 'Error :Conection'
#-----------------------------------------------------------
def Enviar_Teclado(IP,T_actual,ID,Rut):
    global CE_rl
    global P_Mensajes
    CE_cabeceras = {
    "Content-Type" : "application/json",
    "Fuseaccess-Id" : ID,
    "Time-Scan" : T_actual
    }
    CE_url = IP + CE_rl[0]

    CE_datos ='{"rut":"'+Rut+'"}'    #'{"rut":"99158441"}' par rut y ping

    if P_Mensajes:
        print '-------------------------------------'
        print 'envio Teclado'
        print '-------------------------------------'
        print 'URL :'+ CE_url
        print 'Datos :'+ CE_datos
    return Get_Post_try_catch('POST', CE_url, CE_datos, CE_cabeceras, 2)
#-----------------------------------------------------------
def Enviar_QR(IP,T_actual,ID,QR):
    global CE_rl
    global P_Mensajes
    CE_cabeceras = {
    "Content-Type" : "application/json",
    "Fuseaccess-Id" : ID,
    "Time-Scan" : T_actual
    }
    CE_url = IP + CE_rl[1]
    CE_datos ='{"data":"'+QR+'"}'	#'{"data":"991584411234"}'

    if P_Mensajes:
        print '-------------------------------------'
        print 'envio QR'
        print '-------------------------------------'
        print 'URL :'+ CE_url
        print 'Datos :'+ CE_datos
    return Get_Post_try_catch('POST', CE_url, CE_datos, CE_cabeceras, 2)
#-----------------------------------------------------------
def Pedir_Usuarios_Activos(IP,T_actual,ID):
    global CE_rl
    global P_Mensajes

    CE_peticion='NO'
    CE_cabeceras = {
    "Content-Type" : "application/json",
    "Fuseaccess-Id" : ID,
    "Time-Scan" : T_actual
    }
    CE_url = IP + CE_rl[2]
    if P_Mensajes:
        print '-------------------------------------'
        print 'Usuarios_Activos'
        print '-------------------------------------'
        print 'URL :'+ CE_url
    return Get_Post_try_catch('GET_SOLO_CABECERA', CE_url,'', CE_cabeceras, 10000)
#-----------------------------------------------------------
def Enviar_Usuarios(IP,T_actual,ID,Usuarios):
    global CE_rl
    global P_Mensajes
    CE_cabeceras = {
    "Content-Type" : "application/json",
    "Fuseaccess-Id" : ID,
    "Time-Scan" : T_actual
    }
    CE_url = IP + CE_rl[3]
    CE_datos = Usuarios # Usuarios autorizados por el dispositivo

    if P_Mensajes:
        print '-------------------------------------'
        print 'Envio Usuarios'
        print '-------------------------------------'
        print 'URL :'+ CE_url
        print 'Datos :'+ CE_datos
    return Get_Post_try_catch('POST', CE_url, CE_datos, CE_cabeceras, 2)
#-----------------------------------------------------------
def Ping_Protocolo(IP, Protoc):
    IP_Pro = str(Protoc) + '://' + IP
    return Ping (IP_Pro)
#-----------------------------------------------------------
def Ping (IP):
    global CE_rl
    global P_Mensajes
    CE_url = IP + CE_rl[4]
    if P_Mensajes:
        print '-------------------------------------'
        print 'ping'
        print '-------------------------------------'
        print 'URL :'+ CE_url
    return Get_Post_try_catch('GET_SIN_PARAMETROS', CE_url, '', '', 1)
#-----------------------------------------------------------
def Veri_Firmware(IP, T_actual, ID, vercion_Actual_Firmware):
    global CE_rl
    global P_Mensajes
    CE_cabeceras = {
        "Content-Type" : "application/json",
        "Fuseaccess-Id" : ID,
        "Time-Scan" : T_actual
    }
    CE_url = IP + CE_rl[5]
    CE_datos ='{"data":"'+vercion_Actual_Firmware+'"}'#ya con la vercion del dispsotivo
    if P_Mensajes:
        print '-------------------------------------'
        print 'Veri_Firmware'
        print '-------------------------------------'
        print 'URL :'+ CE_url
        print 'Datos :'+ CE_datos
    return Get_Post_try_catch('GET', CE_url, CE_datos, CE_cabeceras, 2)
#-----------------------------------------------------------
def Confimacion_Firmware(IP, T_actual, ID, vercion_Actual_Firmware, LOG):
    global CE_rl
    global P_Mensajes
    CE_cabeceras = {
        "Content-Type" : "application/json",
        "Fuseaccess-Id" : ID,
        "Time-Scan" : T_actual
    }
    CE_url = IP + CE_rl[6]

    if P_Mensajes:
        print '-------------------------------------'
        print 'Confimacion_Firmware'
        print '-------------------------------------'
        print 'URL :'+ CE_url

    if len(LOG)>=2:
        CE_datos ='{"version":"'+vercion_Actual_Firmware+'","updated":"0","log":"'+LOG+'"}'
    else :
        CE_datos ='{"version":"'+vercion_Actual_Firmware+'","updated":"1"}'

    #CE_datos ='{"version":"2019.12.3.0","update":"1"}'#Formato actualisacion correcta
    #CE_datos ='{"version":"2019.12.3.0","update":"0","log":"2.3 herror ...."}' #Formato herror
    return Get_Post_try_catch('POST', CE_url, CE_datos, CE_cabeceras, 2)
#-----------------------------------------------------------
def Pedir_Usuarios_Dentro(IP, T_actual, ID):
    if P_Mensajes:
        print '-------------------------------------'
        print 'Pedir Usuarios Dentro del establecimiento'
        print '-------------------------------------'
    return Enviar_Usuarios(IP, T_actual, ID, '{"in_out":[""]}')
#-----------------------------------------------------------



#-----------------------------------------------------------
#               Pruebas de funcionamiento
#-----------------------------------------------------------

#Get_Post_try_catch(peticion, CE_url, CE_datos, CE_cabeceras, tout):
#Enviar_Teclado('http://plataforma.ifchile.com',str(int(time.time()*1000.0)),'CCCB23102020b827eb529826000002','12354')
#Enviar_QR('http://plataforma.ifchile.com',str(int(time.time()*1000.0)),'CCCB23102020b827eb529826000002','dD3Wmu0p3f1lv9JGBTpWZfYXosQmMaBezhCJr9m2gKYjBDSIXU9t4sW55adM8PqnpF9yJjjHLd8bsz1fWdl0qg==.gm7dmny')
#Pedir_Usuarios_Activos('http://plataforma.ifchile.com',str(int(time.time()*1000.0)),'CCCB23102020b827eb529826000002')
#Ev=Leer_Archivo(7)


#print Pedir_Usuarios_Dentro('https://plataforma.ifchile.com',str(int(time.time()*1000.0)),'CCCB23102020b827eb529826000002') # funciona

#Ev = '{"in_out":[""]}'
#print Enviar_Usuarios('https://plataforma.ifchile.com',str(int(time.time()*1000.0)),'CCCB23102020b827eb529826000002',Ev)
#print Enviar_Usuarios('http://35.164.107.131',str(int(time.time()*1000.0)),'CCCB23102020b827eb529826000002',Ev)

#18.236.119.39

#Ping ('http://plataforma.ifchile.com')
#Veri_Firmware('http://plataforma.ifchile.com',str(int(time.time()*1000.0)),'CCCB23102020b827eb529826000002','2019.12.3.0')


#-----------------------------------------------------------
#-----------------------------------------------------------
#                       RESUMEN y descripciones
#-----------------------------------------------------------
#-----------------------------------------------------------

# Get_Post_try_catch(peticion, CE_url, CE_datos, CE_cabeceras, tout):
# Enviar_Teclado(IP,T_actual,ID,Rut):
# Enviar_QR(IP,T_actual,ID,QR):
# Pedir_Usuarios_Activos(IP,T_actual,ID):
# Enviar_Usuarios(IP,T_actual,ID,Usuarios):
# Ping (IP):
# Veri_Firmware(IP, T_actual, ID, vercion_Actual_Firmware):
# Confimacion_Firmware(IP, T_actual, ID, vercion_Actual_Firmware, LOG):
