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
#---------------------------------
#           Librerias personales
#---------------------------------
from Lib_File import *            # importar con los mismos nombres
from Lib_Rout import *            # importar con los mismos nombres
from Lib_Requests_Server import *  # importar con los mismos nombres


#-------------------------------------------------------
# inicio de variable	--------------------------------------

LMW_Mensajes = 1     # 0: NO print  1: Print

#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
#                   Deisiones para autorizar el Qr
#-------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------
def IP_Valido(IP):
    try:
        socket.inet_aton(IP)
        if IP.count('.') == 3:
            return True
        else:
            return False
    except socket.error:
        return False
#---------------------------------------------------------
def Dominio_Valido(Dominio):
    Resolver = "host -t A  " + Dominio + "   | grep address | awk {'print $4'}"
    address = commands.getoutput(Resolver)
    try:
        if IP_Valido(address):
            return address
        else:
            return False
    except socket.error:
        return False
#---------------------------------------------------------
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

#---------------------------------------------------------
#----       revicion de comandos realisados por web
#---------------------------------------------------------
def Resolver_Comando_Web():

    Comando = Get_File(COM_WEB)
    #print Comando

    if Get_File(COM_WEB_ANTES) != Comando :
        Set_File(COM_WEB_ANTES,Comando)
        print Comando
        Datos = Comando.replace(':','.')

        if LMW_Mensajes: print Datos

        Datos = Datos.split('.')
        #print len(Datos)

        if Datos[0] == 'F':
            print 'Firmware'

            if Firmware(Datos, Comando) == 1:    # print('Restablecer')
                print('Firm')
                #Comando_Procesado(Comando)
                #Comando_Antes = Comando

        if Datos[0] == 'R':
            print 'Restablecer'

            if Restablecer(Datos, Comando) == 1:
                print('Restablecer')
                #Comando_Procesado(Comando)
                #Comando_Antes = Comando

        if Datos[0] == 'T':
            print 'Torniquete'

            if Torniquete(Datos) == 1:
                print('Comunicaciones')#
                #Comando_Procesado(Comando)
                #Comando_Antes = Comando

        if Datos[0] == 'C':
            print 'Comunicaciones'

            if Comunicaciones(Datos) == 1:
                print('Comunicaciones')
                #Comando_Procesado(Comando)
                #Comando_Antes = Comando
                #commands.getoutput('sudo reboot')

#---------------------------------------------------------
#----       Permisos para lecto escritura web
#---------------------------------------------------------
def Permisos_Web():
    commands.getoutput('sudo chown -R www-data:www-data /var/www')
    commands.getoutput('sudo chgrp www-data /var/www/html')
    commands.getoutput('sudo usermod -a -G www-data pi')
    commands.getoutput('sudo chmod -R 775 /var/www/html')
    commands.getoutput('sudo chmod -R g+s /var/www/html')
    commands.getoutput('sudo chown -R pi /var/www/html')
#---------------------------------------------------------
#----       Pagina restablecer metodo de restablecimeito
#---------------------------------------------------------
def Restablecer(Datos, Comando):

    if LMW_Mensajes:
        print('-----------------------------')
        print('Restablecer')

    Con =len(Datos)

    if Datos[1].find("Borrar_Historial") != -1  :
        if LMW_Mensajes:    print('info, Borrando el Historial')
        Set_File(PRO_WEB,'info, Borrando el Historial')

        time.sleep(3)
        if LMW_Mensajes:    print('ok,Borrado el Historial')
        Set_File(PRO_WEB,'ok, Borrando el Historial')
        time.sleep(3)
        Clear_File(PRO_WEB)

        return 1

    if Datos[1].find("Borrar_Base_de_datos") != -1  :
        if LMW_Mensajes:    print('info, Borrando Base de datos')

        Set_File(PRO_WEB,'info, Borrando Base de datos')

        Clear_File(TAB_USER_TIPO_1)
        Clear_File(TAB_AUTO_TIPO_1)
        Clear_File(TAB_PINES_TIPO_1)
        Clear_File(TAB_USER_TIPO_2)
        Clear_File(TAB_AUTO_TIPO_2)
        Clear_File(TAB_USER_TIPO_2_1)
        Clear_File(TAB_AUTO_TIPO_2_1)
        Clear_File(TAB_USER_TIPO_3)
        Clear_File(TAB_AUTO_TIPO_3)

        time.sleep(3)
        if LMW_Mensajes:    print('ok, Borrada la Base de datos')
        Set_File(PRO_WEB,'ok, Borrada la Base de datos')
        time.sleep(3)
        Clear_File(PRO_WEB)

        return 1

    if Datos[1].find("Valores_de_fabrica") != -1  :
        if LMW_Mensajes:    print('info, Configuranco Valores fabrica')

        Set_File(PRO_WEB,'info, Configuranco Valores fabrica')

        #----------------------------------------------------
        #----- Borrar_Base_de_datos -----
        Clear_File(TAB_USER_TIPO_1)
        Clear_File(TAB_AUTO_TIPO_1)
        Clear_File(TAB_PINES_TIPO_1)
        Clear_File(TAB_USER_TIPO_2)
        Clear_File(TAB_AUTO_TIPO_2)
        Clear_File(TAB_USER_TIPO_2_1)
        Clear_File(TAB_AUTO_TIPO_2_1)
        Clear_File(TAB_USER_TIPO_3)
        Clear_File(TAB_AUTO_TIPO_3)

        # ------    led RGB     -----
        Clear_File(COM_LED)
        Set_File(COM_LED,'0')
        # ------    Buzzer     -----
        Clear_File(COM_BUZZER)
        # ------    QR     -----
        Clear_File(COM_QR)
        Clear_File(STATUS_QR)
        Clear_File(STATUS_REPEAT_QR)
        # ------    Torniquete o rele    -----
        Clear_File(CONF_TIEM_RELE)
        Set_File(CONF_TIEM_RELE,'1')
        Clear_File(CONF_DIREC_RELE)
        Set_File(CONF_DIREC_RELE,'D')
        Clear_File(CONF_COMU_RELE)
        Clear_File(COM_TX_RELE)
        Clear_File(COM_RELE)
        # ------    Teclado    -----
        Clear_File(COM_TECLADO)
        Clear_File(STATUS_TECLADO)
        Clear_File(CONF_FLECHA_TECLADO)
        Set_File(CONF_FLECHA_TECLADO,'1')


        #----------------------------------------------------

        time.sleep(3)
        if LMW_Mensajes:    print('ok, Valores fabrica')
        Set_File(PRO_WEB,'ok, Valores fabrica')
        time.sleep(3)
        Clear_File(PRO_WEB)
        return 1

    if Datos[1].find("TS") != -1  :
        if LMW_Mensajes:    print('info, Comenzando Test')

        Set_File(PRO_WEB,'info, Comenzando Test')
        Test_Nuevo_Servidor(Comando,"Test")
        return 1

    if Datos[1].find("CS") != -1  :
        if LMW_Mensajes:    print('info, Comenzando Conexion')

        Set_File(PRO_WEB,'info, Comenzando Conexion')
        Test_Nuevo_Servidor(Comando,"Conectando")
        return 1

    return 0

#---------------------------------------------------------
#----       Pagina Firmware
#---------------------------------------------------------
def Firmware(Datos, Comando):
    if LMW_Mensajes:
        print('-----------------------------')
        print('firmware')


    Set_File(COM_ACTUALIZADOR, '1')

    Set_File(PRO_WEB,'info, Forzando Actualizacion')
    time.sleep(3)

    Set_File(PRO_WEB,'info, Ejecutando  Actualizacion')
    time.sleep(3)
    Clear_File(PRO_WEB)
    return 1

    return 0
#---------------------------------------------------------
#----      Test Nuevo servidor
#---------------------------------------------------------
def Test_Nuevo_Servidor(Comando,tipo):
            N_Servidor1 = Comando.split(':')
            N_Servidor = N_Servidor1[1].strip()
            if LMW_Mensajes:
                print '-----------------------------'
                print N_Servidor
                print '-----------------------------'
            Variable_Dominio=''
            Variable_IP=''
            #textProgreso.set(str(N_Servidor))
            #Progreso_Servidor.pack()
            #Progreso_Servidor.place(bordermode=OUTSIDE, height=30, width=150, x=140, y=60)
            #print '-----------------------------'
            #print N_Servidor
            #print '-----------------------------'
            #print 'hola'

            try:
                    socket.inet_aton(N_Servidor)
                    if N_Servidor.count('.') == 3:
                        print '---------------------------------'
                        print '1. Prueba de coneccion por IP'
                        print '---------------------------------'
                        Set_File(PRO_WEB,'info, Prueba de coneccion por IP')

                        print 'IP :' +str(N_Servidor)
                        Respuesta = Ping_Protocolo(N_Servidor, 'http')
                        #print Respuesta
                        #if Respuesta !='NO':
                        if Respuesta.find("Error") == -1:
                            Check_Res= Check_Respuestas(Respuesta)
                            if Check_Res == True:
                                print 'Esta IP es valida'
                                Set_File(PRO_WEB,'info, Esta IP es valida')
                                #Mensajes('Test OK,Esta IP es valida se cambiara, pero el dominio sera el mismo.','OK')
                            else:
                                print 'Test Error,La IP no Funciona'
                                Set_File(PRO_WEB,'info, La IP no Funciona')
                                #Mensajes('Test Error, '+ str(Check_Res)+' La IP no Funciona.','Error')
                        else:
                            print 'Test Error,La IP no contesto'
                            Set_File(PRO_WEB,'info, La IP no contesto')
                            #Mensajes('Test Error,La IP no contesto.','Error')



            except socket.error:
                    print '---------------------------------'
                    print 'NO es una IP revision por Dominio'
                    print '---------------------------------'
                    Set_File(PRO_WEB,'info, Revision por Dominio')

                    IP = Dominio_Valido(N_Servidor)
                    #print IP
                    if IP != False:

                            Test_IP_Dominio=0
                            print '---------------------------------'
                            print 'Prueba de coneccion por IP'
                            print '---------------------------------'

                            print 'IP :' +str(IP)
                            print 'Con http'
                            Variable_IP = IP
                            Variable_Dominio = N_Servidor
                            Set_File(PRO_WEB,'info, Prueba de coneccion por IP')

                            Respuesta= Ping_Protocolo(IP, 'http')
                            #print Respuesta
                            #if Respuesta !='NO':
                            if Respuesta.find("Error") == -1:
                                Check_Res= Check_Respuestas(Respuesta)

                                if Check_Res == True:
                                    print 'Esta IP es valida'
                                    Test_IP_Dominio=10
                                    #Mensajes('Test OK,Esta IP es valida se cambiara, pero el dominio sera el mismo.','OK')
                                    Set_File(PRO_WEB,'info, Esta IP es valida')
                                else:
                                    print 'Test Error, '+ str(Check_Res)+' La IP no Funciona'
                                    #Mensajes('Test Error, '+ str(Check_Res)+' La IP no Funciona.','Error')
                                    Set_File(PRO_WEB,'info, La IP no Funciona')
                            else:
                                print 'Test Error,La IP no contesto'
                                Set_File(PRO_WEB,'info, La IP no contesto')


                            print 'Con https'

                            Respuesta= Ping_Protocolo(IP, 'https')
                            #print Respuesta
                            #if Respuesta !='NO':
                            if Respuesta.find("Error") == -1:
                                Check_Res= Check_Respuestas(Respuesta)

                                if Check_Res == True:
                                    print 'Esta IP es valida'
                                    Set_File(PRO_WEB,'info, Esta IP es valida')
                                    Test_IP_Dominio=Test_IP_Dominio+100
                                    #Mensajes('Test OK,Esta IP es valida se cambiara, pero el dominio sera el mismo.','OK')
                                else:
                                    print 'Test Error, '+ str(Check_Res)+' La IP no Funciona'
                                    #Mensajes('Test Error, '+ str(Check_Res)+' La IP no Funciona.','Error')
                            else:
                                print 'Test Error,La IP no contesto'
                                Set_File(PRO_WEB,'info, La IP no contesto')


                            print '---------------------------------'
                            print 'Prueba de coneccion por Dominio'
                            print '---------------------------------'
                            Set_File(PRO_WEB,'info, Prueba de coneccion por Dominio')

                            print 'Dominio :' +N_Servidor
                            print 'Con http'

                            Respuesta= Ping_Protocolo(N_Servidor, 'http')
                            #print Respuesta
                            if Respuesta !='NO':
                                Check_Res= Check_Respuestas(Respuesta)
                                if Check_Res == True:
                                    print 'Esta Dominio es valida'
                                    Set_File(PRO_WEB,'info, Esta Dominio es valida')
                                    Test_IP_Dominio=Test_IP_Dominio+1
                                else:
                                    print 'Test Error, '+ str(Check_Res)+' La IP no Funciona'
                                    #Mensajes('Test Error, '+ str(Check_Res)+' La IP no Funciona.','Error')
                            else:
                                print 'Test Error,El dominio no contesto'
                                Set_File(PRO_WEB,'info, El dominio no contesto')

                            print 'Con https'

                            Respuesta= Ping_Protocolo(N_Servidor, 'https')
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
                                Set_File(PRO_WEB,'info, El dominio no contesto')


                            print Test_IP_Dominio

                            if Test_IP_Dominio == 0:    Set_File(PRO_WEB,'error,'+tipo+' 0 Error, http Dominio NO. IP NO; https Dominio NO. IP NO.')
                            if Test_IP_Dominio == 1:    Set_File(PRO_WEB,'ok,'+tipo+' 25%  OK. http Dominio OK. IP NO; https Dominio NO. IP NO.')
                            if Test_IP_Dominio == 10:   Set_File(PRO_WEB,'ok,'+tipo+' 25%  OK. http Dominio NO. IP OK; https Dominio NO. IP NO.')
                            if Test_IP_Dominio == 11:   Set_File(PRO_WEB,'ok,'+tipo+' 50%  OK. http Dominio OK. IP OK; https Dominio NO. IP NO.')

                            if Test_IP_Dominio == 100:  Set_File(PRO_WEB,'ok,'+tipo+' 25%  OK. http Dominio NO. IP NO; https Dominio NO. IP OK.')
                            if Test_IP_Dominio == 101:  Set_File(PRO_WEB,'ok,'+tipo+' 50%  OK. http Dominio OK. IP NO; https Dominio NO. IP OK.')
                            if Test_IP_Dominio == 110:  Set_File(PRO_WEB,'ok,'+tipo+' 50%  OK. http Dominio NO. IP OK; https Dominio NO. IP OK.')
                            if Test_IP_Dominio == 111:  Set_File(PRO_WEB,'ok,'+tipo+' 75%  OK. http Dominio OK. IP OK; https Dominio NO. IP OK.')

                            if Test_IP_Dominio == 1000: Set_File(PRO_WEB,'ok,'+tipo+' 25%  OK. http Dominio NO. IP NO; https Dominio OK. IP NO.')
                            if Test_IP_Dominio == 1001: Set_File(PRO_WEB,'ok,'+tipo+' 50%  OK. http Dominio OK. IP NO; https Dominio OK. IP NO.')
                            if Test_IP_Dominio == 1010: Set_File(PRO_WEB,'ok,'+tipo+' 50%  OK. http Dominio NO. IP OK; https Dominio OK. IP NO.')
                            if Test_IP_Dominio == 1011: Set_File(PRO_WEB,'ok,'+tipo+' 75%  OK. http Dominio OK. IP OK; https Dominio OK. IP NO.')

                            if Test_IP_Dominio == 1100: Set_File(PRO_WEB,'ok,'+tipo+' 50%  OK. http Dominio NO. IP NO; https Dominio OK. IP OK.')
                            if Test_IP_Dominio == 1101: Set_File(PRO_WEB,'ok,'+tipo+' 75%  OK. http Dominio OK. IP NO; https Dominio OK. IP OK.')
                            if Test_IP_Dominio == 1110: Set_File(PRO_WEB,'ok,'+tipo+' 75%  OK. http Dominio NO. IP OK; https Dominio OK. IP OK.')
                            if Test_IP_Dominio == 1111: Set_File(PRO_WEB,'ok,'+tipo+' 100% OK. http Dominio OK. IP OK; https Dominio OK. IP OK.')



                            if tipo == 'Conectando':
                                if Test_IP_Dominio !=0:
                                    if LMW_Mensajes:
                                        print 'guardando y reiniciando'
                                    print Test_IP_Dominio
                                    print Variable_IP
                                    print Variable_Dominio

                                    Set_File(PRO_WEB,'ok,'+tipo+' Guardando y reiniciando.')

                                    Set_File(CONF_IP_SERVER, Variable_IP)
                                    Set_File(CONF_DOMI_SERVER,Variable_Dominio)
                                    Set_File(CONF_M_CONEX_SERVER, str(Test_IP_Dominio))

                                    #commands.getoutput('sudo reboot')

                            time.sleep(3)
                            Clear_File(PRO_WEB)



                    else:
                            print 'Dominio NO Valido, no hay IP asociada'
                            Set_File(PRO_WEB,'error,Dominio NO Valido, no hay IP asociada.')
                            time.sleep(3)
                            Clear_File(PRO_WEB)

#---------------------------------------------------------
#----      pagina de Comunicaciones
#---------------------------------------------------------

def Comunicaciones(Datos):
    if LMW_Mensajes:
        print('-----------------------------')
        print('Comunicaciones')

    Con =len(Datos)
    if Con == 19 :
        if Datos[2].find("Ethernet") != -1  :
            if LMW_Mensajes:
                print "IP: "+Datos[4]+Datos[5]+Datos[6]+Datos[7] + "G: "+Datos[9]+Datos[10]+Datos[11]+Datos[12] + "DN: "+Datos[14]+Datos[15]+Datos[16]+Datos[17] +" Configura Ethernet"
            SIN_IP_Static("Ethernet")
            Ip_Estatica(1, 1, Datos[4]+'.'+Datos[5]+'.'+Datos[6]+'.'+Datos[7], Datos[9]+'.'+Datos[10]+'.'+Datos[11]+'.'+Datos[12], Datos[14]+'.'+Datos[15]+'.'+Datos[16]+'.'+Datos[17])
            return 1
        else                                :
            if LMW_Mensajes:
                print "IP: "+Datos[4]+Datos[5]+Datos[6]+Datos[7] + "G: "+Datos[9]+Datos[10]+Datos[11]+Datos[12] + "DN: "+Datos[14]+Datos[15]+Datos[16]+Datos[17] +"Configura wifi"
            SIN_IP_Static("Wifi")
            Ip_Estatica(1, 0, Datos[4]+'.'+Datos[5]+'.'+Datos[6]+'.'+Datos[7], Datos[9]+'.'+Datos[10]+'.'+Datos[11]+'.'+Datos[12], Datos[14]+'.'+Datos[15]+'.'+Datos[16]+'.'+ Datos[17])
            return 1
    if Con == 4 :
        if Datos[2].find("Ethernet") != -1  :
            if LMW_Mensajes:
                print Datos[2]+Datos[3]+"Ethernet Dinamico"
            #Borrar_Ip_Estatica(1,1)
            SIN_IP_Static("Ethernet")
            return 1
        else                                :
            if LMW_Mensajes:
                print Datos[2]+Datos[3]+"Wifi Dinamico"
            #Borrar_Ip_Estatica(1,0)
            SIN_IP_Static("Wifi")
            return 1
    if Con == 5 :
        if LMW_Mensajes:
            print Datos[2]+Datos[4]+"Nueva wifi"
        red = Datos[2]
        clave = Datos[4]
        commands.getoutput('sudo chmod -R 777 /etc/wpa_supplicant/wpa_supplicant.conf')
        N_wifi='\nnetwork={\n\tssid="'+red+'"\n\tpsk="'+clave+'"\n\tkey_mgmt=WPA-PSK\n\n}'
        if LMW_Mensajes:    print (N_wifi)
        #Nueva_wifi(N_wifi)
        Add_File(CONF_WIF_ETHE, N_wifi)
        return 1
    if Con == 7 :
        if LMW_Mensajes:
            print "IP_counter: "+Datos[3]+'.'+Datos[4]+'.'+Datos[5]+'.'+Datos[6]

        #Borrar(49)
        #Escrivir_Archivo(Datos[3]+'.'+Datos[4]+'.'+Datos[5]+'.'+Datos[6],49)
        return 1


    return 0


def Ip_Estatica(a,we,IP,GD,DNS):

        #Borrar_Ip_Estatica(a,we)
        print 'colocando las ip statica'
        if we==0:   Add_Line_End(CONF_IP_STATIC, 'interface wlan0\n') #Escrivir_Archivo('interface wlan0',44)#f.write('interface wlan0'+'\n')
        else:       Add_Line_End(CONF_IP_STATIC, 'interface eth0\n') #Escrivir_Archivo('interface eth0',44)#f.write('interface eth0'+'\n')
        Add_Line_End(CONF_IP_STATIC,'static ip_address='+IP +'\n') #Escrivir_Archivo('static ip_address='+IP,44)#f.write('static ip_address='+IP+'\n')
        Add_Line_End(CONF_IP_STATIC,'static routers='+ GD +'\n')   # Escrivir_Archivo('static routers='+ GD,44)#f.write('static routers='+ GD+'\n')
        Add_Line_End(CONF_IP_STATIC,'static domain_name_servers= '+ DNS +'\n' )# Escrivir_Archivo('static domain_name_servers='+ DNS,44)#f.write('static domain_name_servers='+ DNS+'\n')



def SIN_IP_Static(Tipo_red):
    print 'borrar ips'
    #Tipo_red = L_Ip_Static_lista.get()
    if Tipo_red == "Ethernet":
            Modificar_Archivo1(1,1,0,1)
    else:
            Modificar_Archivo1(1,0,0,1)



def Modificar_Archivo1(a, we, con_dns, Borrar):

        #global CONF_WIF_ETHE
        #global N_A_IP_Static

        contador =0
        #we =2

        if a==0:	arch	=	CONF_WIF_ETHE
        if a==1:	arch	=	CONF_IP_STATIC

        f = open (arch,'r')
        lineas = f.readlines()
        f.close()

        x=0
        T_fichero = len(lineas)
        #print T_fichero
        #print a

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

        if( Borrar == 0):

            print 'colocando las ip statica'
            if we==0:
                    f.write('interface wlan0'+'\n')
            else:
                    f.write('interface eth0'+'\n')

            if con_dns==0:
                f.write('static ip_address='+ str(IP.get())+'\n')
                f.write('static routers='+ str(Gateway.get())+'\n')
                f.write('static domain_name_servers='+ str(Gateway.get())+'\n')
            else:
                f.write('static ip_address='+ str(IP.get())+'\n')
                f.write('static routers='+ str(Gateway.get())+'\n')
                f.write('static domain_name_servers='+ str(DNS.get())+'\n')


        f.close()

#---------------------------------------------------------
#----      pagina del Torniquete
#---------------------------------------------------------


def Torniquete(Datos):

    if LMW_Mensajes:
        print('-----------------------------')
        print('Torniquete')
        print('info, Configurando Torniquete')


    Set_File(PRO_WEB,'info, Configurando Torniquete')
    Con =len(Datos)
    if Con == 5 :
        if LMW_Mensajes:
            print "Tiempo: "+Datos[2]+", Direccion: "+Datos[4]
            #print Datos[4][0]
        #Escrivir_Estados(str(Datos[4][0]),13)
        #Escrivir_Estados(Datos[2],30)
        Clear_File(CONF_TIEM_RELE)
        Set_File(CONF_TIEM_RELE,str(Datos[2]))
        Clear_File(CONF_DIREC_RELE)
        Set_File(CONF_DIREC_RELE,str(Datos[4][0]))

        time.sleep(3)
        if LMW_Mensajes:
            print('ok, Torniquete configurado')
        Set_File(PRO_WEB,'ok, Torniquete configurado')
        time.sleep(3)
        Clear_File(PRO_WEB)
        return 1

    return 0



"""
R.Borrar_Historial
R.Borrar_Base_de_datos
R.Valores_de_fabrica
R.Nuevo_servidor
T.T:6.D:Izquierda
T.T:9.D:Derecha
C.W:NEWNET2020.P:567uytyu
C.R:WIFI.D
C.W:ACAMRO.P:12312
C.R:Ethernet.I:5464.G:456.D:54646.E
"""
