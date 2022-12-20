#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Libreria personal para procesar un qr.




# ideas a implementar





"""
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
# Librerias creadas para multi procesos o hilos -------------
import datetime
import time
import commands
import sys
import socket
import os


#---------------------------------
#           Librerias personales
#---------------------------------

from lib.Lib_File import *            # importar con los mismos nombres
from lib.Lib_Rout import *            # importar con los mismos nombres
from lib.Lib_Requests_Server import *   #
from lib.Lib_Networks import *   #
from lib.Fun_Dispositivo import *   #
from lib.Fun_Server import *   #
from lib.Fun_Tipo_QR import *   #


#-------------------------------------------------------
# inicio de variable	--------------------------------------

PRS_Mensajes = 1     # 0: NO print  1: Print

"""
def Restablecer():
    global Hay_Internet
    global T_antes
    #Hay_Internet = 1
    if Hay_Internet == 1:
        T = Tiempo()
        #print T
        diferencia =  int( ( (int(T) -int(T_antes) ) /1000) /60)
        #print diferencia
        if diferencia >=1: #-------   Tiempo de intentos cada minuto
            T_antes=T
            #print 'intentar de nuevo'
            if PP_Mensajes:
                print 'NO hay conecion con el servidor ?'
            Ver_Link()
            Estado_Ethernet = Estados_Internet()
            if Estado_Ethernet.find("C") !=-1: #revicion wifi y ethernet
                if PP_Mensajes:
                    print 'Hay coneccion Local'
                Dominio_Prueba = (Leer_Archivo(31)).rstrip()
                if PP_Mensajes:
                    print 'Dominio actual:'+Dominio_Prueba
                IP_Dominio_Actual = Dominio_Valido(Dominio_Prueba)
                if IP_Dominio_Actual !=False:
                    #-------------------------------------
                    #-------- camvio la IP o la configuracion de acceso Test
                    if PP_Mensajes:
                        print 'Adquiere una IP :' + str(IP_Dominio_Actual)
                    #-------------------------------------
                    if Agregar_Nuevo_Servidor(Dominio_Prueba):
                        if PP_Mensajes:
                            print 'actualizar link'
                        Cambiar_LINK() # activar cuando cambie los archivos
                        Ping_Intento_Enviar_Usuarios_Autotizados() #enviar usuarios
                        #Hay_Internet = 0 #prueba de restablesimiento mejorar?
                    else:
                        if PP_Mensajes:
                            print 'Esperar otros errores en el dominio'
                else:
                    #-------------------------------------
                    #-------- Verificando cambio de dominio
                    if PP_Mensajes:
                        print 'Revizar lista de dominios'
                    Nuevo_Dominio = List_Dom() #me devuleve una IP o dominio
                    if PP_Mensajes:
                        print Nuevo_Dominio
                    if Nuevo_Dominio.find("Error") ==-1:
                        if PP_Mensajes:
                            print 'para cambio o'
                        if Agregar_Nuevo_Servidor(Nuevo_Dominio):
                            Cambiar_LINK() # activar cuando cambie los archivos
                            Ping_Intento_Enviar_Usuarios_Autotizados() #enviar usuarios
                            #Hay_Internet = 0 #prueba de restablesimiento mejorar?
                        else:
                            if PP_Mensajes:
                                print 'Esperar otros errores'
                    else:
                        #-------------------------------------
                        #No se puede hacer nada asta que el servidor se restabelsca
                        if PP_Mensajes:
                            print 'Esperar restablecimiento del servidor'

            else:
                if PP_Mensajes:
                    print 'NO hay conecion local'




def Test_Nuevo_Servidor():
            N_Servidor = Nuevo_Servidor.get()
            N_Servidor = N_Servidor.strip()
            #textProgreso.set(str(N_Servidor))
            #Progreso_Servidor.pack()
            #Progreso_Servidor.place(bordermode=OUTSIDE, height=30, width=150, x=140, y=60)
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
                        Respuesta = Ping_Protocolo(N_Servidor, 'http')
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

                            Respuesta= Ping_Protocolo(IP, 'http')
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

                            Respuesta= Ping_Protocolo(IP, 'https')
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

                            Respuesta= Ping_Protocolo(N_Servidor, 'http')
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
                            #print 'Esta IP es valida'
                            Variable_IP=str(N_Servidor)
                            #print Variable_IP
                            Set_File(CONF_IP_SERVER, Variable_IP)
                            # commands.getoutput('sudo reboot')
                            #Mensajes('Test OK,Esta IP es valida se cambiara, pero el dominio sera el mismo.','OK')
                        else:
                            #print 'Test Error,La IP no Funciona'
                            Mensajes('Test Error, '+ str(Check_Res)+' La IP no Funciona.','Error')
                    else:
                        #print 'Test Error,La IP no contesto'
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

                        Respuesta= Ping_Protocolo(IP, 'http')
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

                        Respuesta= Ping_Protocolo(IP, 'https')
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

                        Respuesta= Ping_Protocolo(N_Servidor, 'http')
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

                        Respuesta= Ping_Protocolo(N_Servidor, 'https')
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
                        if Test_IP_Dominio !=0:
                            print 'guardando y reiniciando'
                            print Test_IP_Dominio
                            print Variable_IP
                            print Variable_Dominio

                            #print Variable_IP
                            Set_File(CONF_IP_SERVER, Variable_IP)
                            Set_File(CONF_DOMI_SERVER,Variable_Dominio)
                            Set_File(CONF_M_CONEX_SERVER, str(Test_IP_Dominio))

                            commands.getoutput('sudo reboot')

                else:
                        print 'Dominio NO Valido, no hay IP asociada'
                        Mensajes('Dominio NO Valido, no hay IP asociada.','Error')


"""





while 1:
    #---------------------------------------------------------
    #  Proceso 0: Tiempo de espera para disminuir proceso
    #---------------------------------------------------------
    time.sleep(1)
    #---------------------------------------------------------
    # Proceso 1: verificar conecion lan
    #---------------------------------------------------------
    if Status_Redes() == 1:
        if PRS_Mensajes: print 'Hay lan'
        Ruta            = Get_Rout_server()
        ID_Dispositivo  = Get_ID_Dispositivo()
        Tiempo_Actual = str(int(time.time()*1000.0))  # Tiempo()
        if PRS_Mensajes: print 'Ruta:' + str(Ruta.strip()) + ', UUID:' + ID_Dispositivo

        if 'OK' in Ping (Ruta.strip()):
            if PRS_Mensajes:  print 'Responde el servidor'
        else:
            if PRS_Mensajes:  print 'NO Responde el servidor'
            #Dominio_Serv = Get_File(CONF_DOMI_SERVER).strip()
            #print Dominio_Serv
            #print Validar_Dominio(Dominio_Serv)
            #Ip_Serv = Get_File(CONF_IP_SERVER).strip()
            #print Get_File(CONF_M_CONEX_SERVER)
            
            Respuesta_Dominio = Validar_Dominio(Dominio_Serv)
            if Respuesta_Dominio != False:
                if Ip_Serv  == Respuesta_Dominio:
                    print "cambio de IP"
            else:
                print 'Domino no responde'





    else:
        print 'NOP'
