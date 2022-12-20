
# Librerias creadas para multi procesos o hilos -------------
import datetime
import time
import commands
import sys
import socket


from lib.Lib_File import *  # importar con los mismos nombres
from lib.Lib_Rout import *  # importar con los mismos nombres

import lib.Control_Web
import lib.Control_Archivos
import lib.Control_Fecha
import lib.Control_Ethernet
import lib.Control_Torniquete
#import lib.Control_Switch
import lib.Seguridad
import lib.Generar_PIN
import Couter
import Enviar_Autorizados
import Boton_Salida
import IR



# definiciones para el aplicativo principal -----------------

Resolver_Comando_Web    = lib.Control_Web.Resolver_Comando_Web

Leer_Archivo            = lib.Control_Archivos.Leer_Archivo
Leer_Estado             = lib.Control_Archivos.Leer_Estado
Borrar                  = lib.Control_Archivos.Borrar_Archivo
Escrivir_Estados        = lib.Control_Archivos.Escrivir_Estados
ID                      = lib.Control_Archivos.ID
Estado_Usuario 	        = lib.Control_Archivos.Estado_Usuario
Escrivir_Enviar         = lib.Control_Archivos.Escrivir_Enviar
Escrivir                = lib.Control_Archivos.Escrivir
Escrivir_nuevo          = lib.Control_Archivos.Escrivir_nuevo
Leer                    = lib.Control_Archivos.Leer
Escrivir_Archivo        = lib.Control_Archivos.Escrivir_Archivo
Verificar_PIN           = lib.Control_Archivos.Verificar_PIN
PIN_Usado               = lib.Control_Archivos.PIN_Usado
Estado_Usuario_Tipo_3   = lib.Control_Archivos.Estado_Usuario_Tipo_3


Tiempo                  = lib.Control_Fecha.T_Actual
Hora                    = lib.Control_Fecha.Hora_Actual

Envio                   = lib.Control_Ethernet.envio
U_Activos               = lib.Control_Ethernet.Usuarios_Activos
Ping                    = lib.Control_Ethernet.ping
Serial                  = lib.Control_Ethernet.ID_Tarjeta

Veri_Firmware           = lib.Control_Ethernet.Veri_Firmware #pruebas de actualizar firmware
Confimacion_Firmware    = lib.Control_Ethernet.Confimacion_Firmware #pruebas de actualizar firmware
Estados_Internet        = lib.Control_Ethernet.Estados_Internet
Dominio_Valido          = lib.Control_Ethernet.Dominio_Valido
IP_Valido               = lib.Control_Ethernet.IP_Valido
Cambiar_LINK            = lib.Control_Ethernet.Cambiar_LINK
List_Dom                = lib.Control_Ethernet.Nuevo_Firmware_Listado_Dominios
Agregar_Nuevo_Servidor  = lib.Control_Ethernet.Agregar_Nuevo_Servidor
Ver_Link                = lib.Control_Ethernet.Ver_Link

Entrar                  = lib.Control_Torniquete.Entrar
Salir                   = lib.Control_Torniquete.Salir

MD5                     = lib.Seguridad.MD5

Generar_PIN             = lib.Generar_PIN.Generador_Pines

#Switch                  = lib.Control_Switch.Get_Switch
#Borrar_BD               = lib.Control_Switch.Borrar_BD


# inicio de variable	--------------------------------------
PP_Mensajes = 0     # 0: NO print  1: Print


Direc_Torniquete = Leer_Estado(13)  #print Direc_Torniquete
Estados = '6' #estados del dispositivos para visualizar en los leds
Estados_Antes = '0'
T_estado = 0

E_Actualizacion=0
R_Actualizacion=0 # actualizar en otromomento
A_Actualizacion=0 # bloque

Hay_Internet = 0  # estados del internet
Escrivir_Estados('0',28)#estado comunicaion servidor
Estado_Internet = 0
#--------------------------------
# variablee proceso actualizador de firmware
E_Actualizacion_Firmware=0
R_Actualizacion_Firmware=0 # actualizar en otromomento
A_Actualizacion_Firmware=0 # bloque
#--------------------------------
#--------------------------------
# variablee proceso actualizador de firmware
Cantidad_Pines = 4

#--------------------------------
# tiempo antes para restableser el dispotivo por periodos de un minuto
T_antes=0
# Funciones	--------------------------------------

def Log_Reinicio():
    if PP_Mensajes:
        print 'hola'
    #Contador = str(int(Leer_Estado(14))+1)
    #print 'Log Reinicio: '+ Contador
    #Borrar(14)              # Borrar QR
    #Escrivir_Estados(Contador,14)   # Guardar QR


def Filtro_Caracteres(s): # eliminar los caracteres y estructura Jason

    s = s.replace('"',"")
    s = s.replace('[',"")
    s = s.replace('{',"")
    s = s.replace(']',"")
    s = s.replace('}',"")
    s = s.replace('data:',"")
    s = s.replace(',',"\r\n")
    return s

def Cambio_Estado_Led(Es):

    global Estados
    Estados = Es
    Led_Estados()


def Led_Estados():

    global Estados
    global Estados_Antes

    if Estados_Antes != Estados:
        Estados_Antes = Estados
        Escrivir_Estados(Estados,3)
        Escrivir_Estados(Estados,10)

def Intentos_Actualizar_Usuarios(Cantidad):

    global Cantidad_Pines

    Cambio_Estado_Led('8')
    for Intentos in range(Cantidad):
        if PP_Mensajes:
            print 'Intento '+str(Intentos)+', Actualizar usuarios'
        if actualizar_usuarios_por()==1:
            break
        else:
            if PP_Mensajes:
                print 'NO actualizo'
    #Generar_PIN(Cantidad_Pines)
    Cambio_Estado_Led('6')


def Guardar_usuarios_sin_salir():

    Ev = Leer()
    #print len(Ev)
    Ev = Ev.replace('\n','","')
    Ev = '{"in_out":["'+Ev+'"]}'
    Ev = Ev.replace('",""]}','"]}')
    Ev = Ev.replace(',""','')
    #print Ev
    T_A = Tiempo()
    ta=Envio(Ev,T_A,3)
    if ta.find("Error") == -1:
        Borrar(2) 		# vaciar usarios enviados
        s = ta
        s= Filtro_Caracteres(s)
        if len(s) != 0:
            if PP_Mensajes:
                print s
            Escrivir_nuevo(1,s) #agregar usuarios que estan aun dentro
    else:
        if PP_Mensajes:
            print 'No se puedo enviar los usuarios'		#programar una nueva entrega

def Enviar_usuarios_Autorizados_Sin_Internet():

    Ev = Leer()
    #print len(Ev)
    if len(Ev) !=0 :
        Ev = Ev.replace('\n','","')
        Ev = '{"in_out":["'+Ev+'"]}'
        Ev = Ev.replace('",""]}','"]}')
        Ev = Ev.replace(',""','')
        if PP_Mensajes:
            print Ev
        T_A = Tiempo()
        ta=Envio(Ev,T_A,3)

        if ta.find("Error") == -1:
            Borrar(2) 		        # vaciar usarios enviados
            s = ta
            s= Filtro_Caracteres (s)
            if len(s) != 0:
                Escrivir_nuevo(1,s)     #al que pensar si los coloco en lectura como nuevo o no
                if PP_Mensajes:
                    print s           #que hacer con los que se quedarono
                return 1                #se iso la entrega y se guardo los usuarios
        else:
            if PP_Mensajes:
                print 'No se puedo enviar los usuarios'		#programs una nueva entrega
            return -1

    else:
        if PP_Mensajes:
            print 'No hay nada para enviar'					# curso normal
        return 2 # se iso la entrega y se guardo los usuarios

    return 1


def actualizar_usuarios_por():
        if PP_Mensajes:
            print "actualizar usuarios por"
        T_A = Tiempo()
        # actualizar usuarios
        Us_acti=U_Activos(T_A)

        if Us_acti.find("Error") == -1:
            s= Filtro_Caracteres (Us_acti)
            #print s
            Escrivir_nuevo(0,s)
            if PP_Mensajes:
                print "ACTUALIZADO por"
            Borrar(1)		#vaciar usurios lectura
            Guardar_usuarios_sin_salir()
            #print Us_acti

            return 1
        else:
            if PP_Mensajes:
                print "No se puedo Actualizar por"
            print Us_acti
            return -1


def Procedimiento_Actualizar_Usuarios():

    global E_Actualizacion
    global R_Actualizacion
    global A_Actualizacion

    E_Actualizacion = 1
    if PP_Mensajes:
        print "actualizar usuarios"
    # actualizar usuarios
    T_A = Tiempo()
    Us_acti=U_Activos(T_A)

    if Us_acti.find("Error") == -1:
        s = Us_acti
        #print "Usuarios:"+ s
        #if (s.find("Access denied") == -1) and (s.find("errors") == -1) and (s.find('status":500') == -1) and (s.find('404 Not Found') == -1): #mejorar  el filtro
        s= Filtro_Caracteres (s)
        #print s
        Escrivir_nuevo(0,s)
        R_Actualizacion=0
        A_Actualizacion=0
        if PP_Mensajes:
            print "ACTUALIZADO"
        Borrar(1)		#vaciar usurios lectura
        Guardar_usuarios_sin_salir()

    else :
        if PP_Mensajes:
            print "No se puedo Actualizar"#Us_acti
        R_Actualizacion=1 # actualizar en otromomento

def Actualizar_Usuarios(Hora_Actualizacion):

        global E_Actualizacion
        global R_Actualizacion
        global A_Actualizacion
        global Cantidad_Pines

        if Hora_Actualizacion ==1:
            Procedimiento_Actualizar_Usuarios()
            #Generar_PIN(4)
        elif Hora() == Hora_Actualizacion and E_Actualizacion == 0:
            Procedimiento_Actualizar_Usuarios()
            #Generar_PIN(Cantidad_Pines)
            Borrar(27)

        if Hora() != Hora_Actualizacion and A_Actualizacion==0:
                if PP_Mensajes:
                    print 'habilitacion hora actualizacion'
                A_Actualizacion=1
                E_Actualizacion=0

def Ping_Intento_Enviar_Usuarios_Autotizados():

    global Hay_Internet
    global Estado_Internet
    if PP_Mensajes:
        print 'Ping antes de enviar'
    Res_Ping=Ping()
    if Res_Ping == 'OK':
        a=Enviar_usuarios_Autorizados_Sin_Internet()
        if		a == 1 :
            Hay_Internet = 0
            Escrivir_Estados('0',28)#estado comunicaion servidor
            if PP_Mensajes:
                print "Se enviaron los usuarios y se guardo correctamente"
        elif	a == 2 :
            Hay_Internet = 0
            if PP_Mensajes:
                print "No hay nada que enviar"

        else:
            if PP_Mensajes:
                print "NO fue posiple enviar los usuarios en otra oportunidad con internet"
            Hay_Internet = 1
            Escrivir_Estados('1',28)#estado comunicaion servidor
            Estado_Internet = 0
        actualizar_usuarios_por();# colocar esta consula 30_05_2019, 16_12_2020:puede demoar demaciado
    else:
        if PP_Mensajes:
            print 'NO hay internet, se sige aurorizando'


def Decision_Torniquete (Res, QR, ID2, Ti,Qr_Te, I_N_S ):

    global Estados


    #print Qr_Te
    #print ID2
    if Qr_Te == '1'	:	Co = QR+'.'             #QR
    elif Qr_Te == '2'	:	Co = QR+'.'+ID2+'.'     #PIN
    else :
        if ID2 != -1	:	Co = QR+'.'+ID2+'.'     #RUT
        else		:	Co=''
    #print Co
    Res=Res.rstrip('\n')#se coloca para pruebas
    Res=Res.rstrip('\r')#se coloca para pruebas
    #c
    if Res == 'Access granted-E':
        if PP_Mensajes:
            print "Entrada, estado 3"
        if Direc_Torniquete == 'D':
            Cambio_Estado_Led('4')
            Salir()
        else :
            Cambio_Estado_Led('3')
            Entrar()
        #print Co
        #print Ti
        if PP_Mensajes:
            print Co+Ti+'.'+Qr_Te+'.0.'+I_N_S

        Escrivir(Co+Ti+'.'+Qr_Te+'.0.'+I_N_S)               #guardar un registro
        Escrivir_Archivo(Co+Ti+'.'+Qr_Te+'.0.'+I_N_S, 22)   #Para dispotivos asociados

        if Qr_Te == '2':    Escrivir_Archivo(Co+Ti+'.'+Qr_Te+'.0.'+I_N_S, 27)   #escrivir pin usado
        if I_N_S == '1':	Escrivir_Enviar(Co+Ti+'.'+Qr_Te+'.0.'+I_N_S)

        Cambio_Estado_Led('0')  #volver a estado de inicio


    elif Res == 'Access granted-S':
        if PP_Mensajes:
            print "Salida, estado 4"
        if Direc_Torniquete == 'D':
            Cambio_Estado_Led('3')
            Entrar()
        else :
            Cambio_Estado_Led('4')
            Salir()

        #print Co
        #print Ti
        if PP_Mensajes:
            print Co+Ti+'.'+Qr_Te+'.1.'+I_N_S

        Escrivir(Co+Ti+'.'+Qr_Te+'.1.'+I_N_S)               #guardar un registro
        Escrivir_Archivo(Co+Ti+'.'+Qr_Te+'.1.'+I_N_S, 22)   #Para dispotivos asociados

        if Qr_Te == '2':    Escrivir_Archivo(Co+Ti+'.'+Qr_Te+'.1.'+I_N_S, 27)   #escrivir pin usado
        if I_N_S == '1':	Escrivir_Enviar(Co+Ti+'.'+Qr_Te+'.1.'+I_N_S)

        Cambio_Estado_Led('0')  #volver a estado de inicio

    else :
        if PP_Mensajes:
            print "No Esta  activo"
        #print "Sin Acceso o rut equivocado estado 5 0 6"

        Cambio_Estado_Led('6')  # realisa un tiempo de visualisacion


def Get_QR_RUT(QR_RUT):

    Pal=''
    if QR_RUT == 'QR':      Pal=Leer_Estado(7)
    elif QR_RUT == 'PIN':
        Pal=Leer_Estado(5)

    else:                   Pal=Leer_Estado(5)
    Pal=Pal.rstrip('\n')
    Pal=Pal.rstrip('\r')

    return Pal

def Respuesta_Sin_Internet(QR_RUT, T_A,  IDQ_Encrip, QR):

    global Cantidad_Pines
    if QR_RUT == 'QR':
        if PP_Mensajes:
            print "Respuesta QR, sin internet:"
        Cambio_Estado_Led('7')
        if PP_Mensajes:
            print 'ID:'+IDQ_Encrip
        #IDQ_Encrip, Resp = Estado_Usuario(IDQ_Encrip,1)
        #print '----- resolviendo respuesta'
        #print 'Resp:'+ Resp

        #------------------------------------------------------------
        #               NUEVO FORMATO CON TINPO INCIO Y FIN
        #------------------------------------------------------------
        puntos = QR.count(".")
        if PP_Mensajes:
            print puntos





        if puntos == 1:
            IDQ_Encrip, Resp = Estado_Usuario(IDQ_Encrip,1)
            if PP_Mensajes:
                print '-----Formato 1: resolviendo respuesta '
                print 'Resp:'+ Resp
            Decision_Torniquete (Resp,QR,"",T_A,'1','1')

        elif puntos == 2:
            IDQ_Encrip, Resp = Estado_Usuario(IDQ_Encrip,1)
            if PP_Mensajes:
                print '-----Formato 2: resolviendo respuesta '
                print 'Resp:'+ Resp
            Decision_Torniquete (Resp,QR,"",T_A,'1','1')

        elif puntos == 3:
            #print 'QR:'+ QR
            SQR = QR.split('.')
            #print SQR[0]
            #print SQR[1]
            inicio = str(int(SQR[2]))
            fin = str(int(SQR[3]))
            #print 'T inicio:' + inicio
            #print 'T fin:' + fin

            #print 'T inicio:' + str(datetime.datetime.fromtimestamp(int(float(inicio)/1000)))
            #print 'T Actual:' + str(datetime.datetime.fromtimestamp(int(float(T_A)/1000)))
            #print 'T Fin   :' + str(datetime.datetime.fromtimestamp(int(float(fin)/1000)))

            if (inicio <= T_A) and (T_A <= fin):
                if PP_Mensajes:
                    print 'Dentro del rango permitido'
                    print SQR[1]
                IDQ_Encrip, Resp = Estado_Usuario(SQR[1],1)
                print '----- resolviendo respuesta'
                print 'Resp:'+ Resp

                Decision_Torniquete (Resp,QR,"",T_A,'1','1')

            else:
                if PP_Mensajes:
                    print 'finalizo NO esta dentro del rango'
                Decision_Torniquete ('Denegar',QR,"",T_A,'1','1')
            """
            if (T_A < inicio) :
                if PP_Mensajes:
                    print 'Aun no comienza'
                #print 'Denegar Entrada'
                Decision_Torniquete ('Denegar',QR,"",T_A,'1','1')
            if (T_A > fin) :
                if PP_Mensajes:
                    print 'finalizo'
                if Resp == 'Access granted-E':
                    if PP_Mensajes:
                        print 'Denegar Entrada'
                    Decision_Torniquete ('Denegar',QR,"",T_A,'1','1')
                elif Resp == 'Access granted-S':
                    if PP_Mensajes:
                        print 'Permitir salida'
                    Decision_Torniquete (Resp,QR,"",T_A,'1','1')
            """
        elif puntos == 4:

            #print 'QR:'+ QR
            SQR = QR.split('.')
            #print SQR[0]
            #print SQR[1]
            #print SQR[1]
            #ID =  SQR[1] + '.' + SQR[2]
            ID =  SQR[1] + '.' + SQR[2]+ '.' + SQR[3]

            #print 'Tipo 3 QR:'
            #print 'ID:'+ ID
            T_inicio = int(SQR[4])
            inicio = str(T_inicio)
            #fin = str(int(SQR[3]))
            #print 'T inicio:' + inicio
            #print 'T Actual: ', str(T_A)

            #quemar 60 minutos   3600 segundos

            if T_A > T_inicio :
                #print 'Ya paso'
                Resta = (int(T_A) -int(SQR[4]))/1000
                if Resta >=3600 :
                    #print 'vencido'
                    Decision_Torniquete ('Denegar',QR,"",T_A,'1','1')
                else:
                    #print 'a tiempo'
                    IDQ_Encrip, Resp = Estado_Usuario_Tipo_3(ID,1)
                    if PP_Mensajes:
                        print '-----Formato 3: resolviendo respuesta '
                        print 'Resp:'+ Resp

                    Decision_Torniquete (Resp,QR,"",T_A,'1','1')

                    Dato_Resp =''
                    if Resp == 'Access granted-E':
                        
                        Dato_Resp = QR+'.'+T_A+'.'+'1'+'.0.'+'1'
                        print 'guardando'#no enviar null
                        Add_File(CONT_AUTORIZADOS,Dato_Resp+'\n')
                        Set_File(CONT_FlAG_AUTORIZADOS,'1')

                    if Resp == 'Access granted-S':
                        Dato_Resp = QR+'.'+T_A+'.'+'1'+'.1.'+'1'
                        print 'guardando'#no enviar null
                        Add_File(CONT_AUTORIZADOS,Dato_Resp+'\n')
                        Set_File(CONT_FlAG_AUTORIZADOS,'1')

            else:
                #print 'futuro'
                Decision_Torniquete ('Denegar',QR,"",T_A,'1','1')

                #print 'Resta tiempo segundos:' + str(Resta)
                #print 'Resta tiempo minutos:' + str(Resta/60)
                #print 'Resta tiempo horas:' + str((Resta/60)/60)

                #print 'T inicio:' + str(datetime.datetime.fromtimestamp(int(float(inicio)/1000)))




            #Decision_Torniquete (Resp,QR,"",T_A,'1','1')


        else:
                #---- mantener formato anterios
                #IDQ_Encrip, Resp = Estado_Usuario(IDQ_Encrip,1)
                #Decision_Torniquete (Resp, QR, "", T_A, '1', '1')
                Decision_Torniquete ('Denegar',QR,"",T_A,'1','1')

        #------------------------------------------------------------
        #------------------------------------------------------------

        #Decision_Torniquete (Resp,QR,"",T_A,'1','1')

    elif QR_RUT == 'PIN':
        if PP_Mensajes:
            print "Respuesta PIN, sin internet:"
        Cambio_Estado_Led('7')
        IDT, Resp = Estado_Usuario(IDQ_Encrip,0)  #++ revizar
        #print Resp
        if IDT!= -1 :
            if PP_Mensajes:
                print 'ID:'+IDT

        #print 'PIN en verificacion:' + QR #pin
        #verificar pin //////// cambia de denegado si no esta elpin
        if Verificar_PIN(IDT,QR) == 0:
            Resp = 'Denegado'

        if Resp != 'Denegado':
            Usado,C_Pines,Usos = PIN_Usado(IDT,QR,Cantidad_Pines)
            #print Usado
            #print Usos
            #print C_Pines
            #print C_Pines/Cantidad_Pines

            if Usos > C_Pines/Cantidad_Pines: # Rpeticion de pines cadaves que se quemen todos
                Resp = 'Denegado'
            else:
                if PP_Mensajes:
                    print 'volver a activarlos'

        print Resp
        #falta proceso de quemar pines y repeticion si ya se terminaron

        if IDT == -1 : IDT = ''

        Decision_Torniquete (Resp,QR,IDT,T_A,'2','1') #revizar
    else:
        if PP_Mensajes:
            print "Respuesta RUT, sin internet:"
        Cambio_Estado_Led('7')
        IDT, Resp = Estado_Usuario(IDQ_Encrip,0)
        if PP_Mensajes:
            print Resp
        if IDT!= -1 :	print 'ID:'+IDT
        Decision_Torniquete (Resp,"",IDT,T_A,'0','1')

def Respuesta_Con_Internet(QR_RUT, T_A,  IDT, Respuesta, QR):

    if QR_RUT == 'QR':
        #Respuesta = Respuesta.text
        if PP_Mensajes:
            print "Respuesta QR, con internet:"+ Respuesta
        Cambio_Estado_Led('1')
        Decision_Torniquete (Respuesta,QR,"",T_A,'1','0')
    elif QR_RUT == 'PIN':
        #Respuesta = Respuesta.text
        if PP_Mensajes:
            print "Respuesta PIN, con internet:"+ Respuesta
        if IDT == -1 : IDT = ''
        Decision_Torniquete (Respuesta,QR,IDT,T_A,'2','0')#revizar
    else:
        #Respuesta = Respuesta.text
        if PP_Mensajes:
            print "Respuesta RUT, con internet:"+ Respuesta
        Decision_Torniquete (Respuesta,"",IDT,T_A,'0','0')

def Decision(QR_RUT):

    global Hay_Internet

    T_A = Tiempo()
    if PP_Mensajes:
        print 'Nuevo------------------------------------'
        print 'Tiempo: ', "%s" % T_A
    # Prepararacion de informacion para tratamiento

    if QR_RUT == 'RUT':
        R_Q = Get_QR_RUT('RUT')
        Encrip=MD5(R_Q)
        ID_Tratado = Encrip
        IDT = ID(Encrip)
        Envio_Dato = R_Q
        Estado_RQ = 0
        Dato2 = ''
        Dato1 = IDT
    elif QR_RUT == 'PIN':
        #print 'Aqui estamos'
        R_Q = Get_QR_RUT('PIN')
        #R_Q = R_Q.replace("K","")
        temp = len(R_Q)
        RUT_T = R_Q[:temp -4]
        PIN_T = R_Q.replace(RUT_T,"")
        #if len (RUT_T)<=0: RUT_T='0'

        Encrip=MD5(RUT_T)
        #if len (Encrip)<=0: Encrip='0'
        ID_Tratado = Encrip
        IDT = ID(Encrip)
        Envio_Dato = R_Q #RUT_T
        Estado_RQ = 2
        Dato2 = PIN_T #'' # campo vacio
        Dato1 = IDT
        if PP_Mensajes:
            print 'RUT:' + RUT_T + ' PIN:' + PIN_T + ' ID:' + str(Dato1)

    else: # QR
        Escrivir_Estados('1',6)# activar sonido por 500*2
        R_Q = Get_QR_RUT('QR')
        #print R_Q
        puntos = R_Q.count(".")
        if PP_Mensajes:
            print puntos
        if puntos == 0:
            IDQ = ''
            QRT = ''
        else:
            s =R_Q.split(".")
            QRT = s[0]
            IDQ = s[1]

        #TDQ = s[2]
        #print 'hola---'
        #print QRT
        #print IDQ
        #print TDQ

        #if IDQ.find(".") == -1:
        ID_Tratado = IDQ
        Envio_Dato = QRT
        Estado_RQ = 1
        Dato2 = R_Q
        Dato1 = ''

    if PP_Mensajes:
        print QR_RUT+': '+ R_Q

    # Decision dependiendo del estado del internet
    #Hay_Internet =1 # /////////////////////////// hojo comentar
    if Hay_Internet == 0	:   # Hay internet

        Respuesta=Envio(Envio_Dato,T_A, Estado_RQ)
        #print Respuesta
        #print Respuesta.text
        #if Respuesta!='NO': #respuesta del servidor
        if Respuesta.find("Error") == -1:

            Respuesta_Con_Internet(QR_RUT, T_A, Dato1, Respuesta, Dato2)
            Hay_Internet = 0
            Escrivir_Estados('0',28)#estado comunicacion servidor

        elif Respuesta.find("Error :Access denied") != -1:
            Respuesta_Con_Internet(QR_RUT, T_A, Dato1, Respuesta, Dato2)
            Hay_Internet = 0
            Escrivir_Estados('0',28)#estado comunicacion servidor

        else :  # Sin internet Momentanio
            if PP_Mensajes:
                print 'nueva evaluacion'
                print ID_Tratado
            Respuesta_Sin_Internet(QR_RUT,T_A, ID_Tratado, Dato2)
            Hay_Internet = 1
            Escrivir_Estados('1',28)#estado comunicaion servidor
            Estado_Internet = 0


    else :      # Sin internet Permanente
        Respuesta_Sin_Internet(QR_RUT,T_A, ID_Tratado, Dato2)

        #Intento de actualizar usuarios
        #Ping_Intento_Enviar_Usuarios_Autotizados()


def  Procedimiento_Actualizar_Firmware():
    global E_Actualizacion_Firmware
    global R_Actualizacion_Firmware
    global A_Actualizacion_Firmware
    if A_Actualizacion_Firmware==1:
        E_Actualizacion_Firmware=1
        A_Actualizacion_Firmware=0
        if PP_Mensajes:
            print 'Proceso de revision del firmware'
        Respuesta = Veri_Firmware(Tiempo(), Leer_Archivo(17).replace('\n',''))       #enviar peticion a servidor

        if Respuesta.find("Error") == -1:
            #if Respuesta!='NO': #respuesta del servidor
            #print Respuesta.text
            # -------------------------------
            #       sacar informacion
            #s = Filtro_Caracteres(Respuesta.text)
            s = Filtro_Caracteres(Respuesta)

            s=s.partition('\n')
            s1 = s[0].replace('id:','')
            ID_F = s1.replace('\r','')
            s2 = s[2].partition('\r')
            s3 = s2[0].replace('version:','')
            Vercion_F =s3.replace('\r','')
            Git_F = s2[2].replace('\r','')
            Git_F = Git_F.replace('\n','')
            Git_F = Git_F.replace('github:','')

            #--------------------------------
            if PP_Mensajes:
                print 'ID: '+ ID_F + ' vercion: '+Vercion_F + ' git: '+Git_F

            if ID_F=='OK':
                if PP_Mensajes:
                    print 'Estoy actualizado'
            else:
                #print Leer_Estado(20) # Estado Actualizador
                if Leer_Estado(20) == '0': # estado inicial de actualizacion firmware
                    if PP_Mensajes:
                        print 'Estado incial'
                    Verificar_Actualizacion(ID_F, Vercion_F, Git_F) #activar cuuando se quiea actualizar

        else :
            if PP_Mensajes:
                print 'NO contesto el servidor'


def Actualizar_Firmware(Hora_Actualizacion):

        global E_Actualizacion_Firmware
        global R_Actualizacion_Firmware
        global A_Actualizacion_Firmware

        if Leer_Archivo(40) == '1': # forzando la actualizacion por Teclado
            Borrar(40)
            A_Actualizacion_Firmware=1
            E_Actualizacion_Firmware=0
            Procedimiento_Actualizar_Firmware()

        if Hora() == Hora_Actualizacion and E_Actualizacion_Firmware == 0: Procedimiento_Actualizar_Firmware()

        if Hora() != Hora_Actualizacion and A_Actualizacion_Firmware==0:
                if PP_Mensajes:
                    print 'Habilitacion hora actualizacion Firmware'
                A_Actualizacion_Firmware=1
                E_Actualizacion_Firmware=0

        if Leer_Archivo(20) == '3':
            if PP_Mensajes:
                print 'Hay una terminacion de firmware enviar respuesta al servidor'
            Ultimo = ""
            res16 = Leer_Archivo(19) # Leer en donde va el proceso de actualizacion
            #print res16
            #print len (res16)

            if len (res16) != 0:

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
            if PP_Mensajes:
                print Ultimo
            if Ultimo == '12.3':
                if PP_Mensajes:
                    print 'Enviar respuesta al servidor Correcta'
                Borrar(20)                  # Estado Actualizador
                Escrivir_Estados('0',20)    # Estado Actualizador
                Borrar(19)                  # log
                #antes de enviar respues actualizar el actualizador
                Actualizar_Actualizador()

                print Confimacion_Firmware(Tiempo(), Leer_Archivo(17).replace('\n',''),'')

        if Leer_Archivo(20) == '5':
            Ultimo = ""
            res16 = Leer_Archivo(19) # Leer en donde va el proceso de actualizacion
            #print res16
            #print len (res16)

            if len (res16) != 0:

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

            Borrar(20)                  # Estado Actualizador
            Escrivir_Estados('0',20)    # Estado Actualizador
            Borrar(19)                  # log
            if PP_Mensajes:
                print Ultimo
            print Confimacion_Firmware(Tiempo(), Leer_Archivo(17).replace('\n',''),Ultimo)





def Actualizar_Actualizador():

    #Log_Actualizador('4. Cambiar nombre de firmware en ejecucion')
    res = commands.getoutput('[ ! -f /home/pi/ActualizadorBK ] && echo "Existe" || echo "NO exiete"')
    if res == 'Existe':
        if PP_Mensajes:
            print 'Eliminar BK'
        res = commands.getoutput('sudo rm -R' + ' /home/pi/ActualizadorBK')
        print res

    res = commands.getoutput('mv /home/pi/Actualizador /home/pi/ActualizadorBK')
    res = commands.getoutput('cp -r /home/pi/Firmware/Actualizador /home/pi/Actualizador')
    res = commands.getoutput('chmod -R 755 /home/pi/Actualizador/sh/app_Actualizando.sh')
    if PP_Mensajes:
        print 'Respuesta:'+ res


def Verificar_Actualizacion ( ID_F, Vercion_F, Git_F):

    if ID_F !=  Serial :
        if PP_Mensajes:
            print 'NO es para mi'
        return '0'

    C =str(Leer_Archivo(17))  # vercion firmware
    if C.find(Vercion_F) != -1 :
        if PP_Mensajes:
            print 'ya esta actualizado'
        return '0'
    else:
        if PP_Mensajes:
            print 'Devo actualizar'
        # cambiar estado y  guarrdar los datos
        Borrar(15)
        Escrivir_Archivo(ID_F,15)
        Escrivir_Archivo(Vercion_F,15)
        Escrivir_Archivo(Git_F,15)

        Borrar(20)              #
        Escrivir_Estados('1',20)   # Estado inicial del actualizador
        return '1'

    return '2'


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

   	#---------------------------------------------------------
	#----						    ------
	#----				 Programa principal ------
	#----						    ------
	#---------------------------------------------------------



if PP_Mensajes:
    print 'Serial: ' + Serial


Log_Reinicio()

if PP_Mensajes:
    print 'LISTO: ' + Hora()

Intentos_Actualizar_Usuarios(3)

#A_Actualizacion_Firmware =1
#Procedimiento_Actualizar_Firmware()
if (Leer_Estado(47)).find("OK") != - 1:
    commands.getoutput('sudo chgrp www-data /var/www/html')
    commands.getoutput('sudo usermod -a -G www-data pi')
    commands.getoutput('sudo chmod -R 775 /var/www/html')
    commands.getoutput('sudo chmod -R g+s /var/www/html')
    commands.getoutput('sudo chown -R pi /var/www/html')


print 'while'

while 1:
    Hay_Internet = 1
    #------------------if PP_Mensajes:---------------------------------------
    #  Proceso 0: Tiempo de espera para disminuir proceso
    #---------------------------------------------------------
    time.sleep(0.05)
    #---------------------------------------------------------
    # Proceso 1: visualizacion de estados del programa
    #---------------------------------------------------------
    Led_Estados()
    if Estados == '6': #Tiempo para el blink Estados 5 0 6
        T_estado +=1
        if T_estado >=10:
            Estados = '0'
            T_estado = 0
    #---------------------------------------------------------
    # Proceso 2: Actualizacion de usuarios para revicion de usuarios sin internet
    #---------------------------------------------------------
    Actualizar_Usuarios("12:10 AM") # 12:00 AM     03:59 PM # hora chile  10:00 PM 12:10 AM

    #---------------------------------------------------------
    # Proceso 3: Procesamiento del PIN
    #---------------------------------------------------------
    #if Leer_Estado(4) == '1':   # Hay un RUT sin procesar
    #    Decision('PIN')
    #    Borrar(4)               #final del proceso

    #---------------------------------------------------------
    # Proceso 3: Procesamiento del Rut
    #---------------------------------------------------------
    #if Leer_Estado(4) == '1':   # Hay un RUT sin procesar
    #    Decision('RUT')
    #    Borrar(4)               #final del proceso
    #---------------------------------------------------------
    # Proceso 4: Procesamiento del QR
    #---------------------------------------------------------
    if Leer_Estado(8) == '1':   # Hay un QR sin procesar
        Decision('QR')
        Borrar(8)               #final del proceso
    #---------------------------------------------------------
    # Proceso 5: enviar usario autorizados sin internet, cuando hay internet y actualizar si no se pudo
    #---------------------------------------------------------
    # cada dos horas enviar los Usuarios

    Enviar_Autorizados.Proceso_envio_Usuarios()

    """
    if Hay_Internet == 0 and Estado_Internet == 0:
        Estado_Internet =1;
        # hay internet y se verifico
        a=Enviar_usuarios_Autorizados_Sin_Internet()
        if PP_Mensajes:
            if	a == 1 :	print "Se enviaron los usuarios y se guardo correctamente"
            elif	a == 2 :	print "No hay nada que enviar"
            else:	                print "NO fue posiple enviar los usuarios en otra oportunidad con internet" # hacer algo mas o espera nueva oportunidad

        if R_Actualizacion==1:
            Actualizar_Usuarios(1)
            if R_Actualizacion==0:
                if PP_Mensajes:
                    print 'se actualizo por usuario con internet'
            else:
                if PP_Mensajes:
                    print 'no se apodifo se espera otra opertunidad'
    """
    #---------------------------------------------------------
    # Proceso 6: Actualizacion de firmware
    #---------------------------------------------------------
    #NOTA: Acer actualizacion de firmware despeue de actualizar usuarios
    Actualizar_Firmware("01:00 AM") # 12:00 AM     03:59 PM 04:07 PM # hora chile  11:00 PM
    #---------------------------------------------------------
    # Proceso 7: Switch de Seguridad para dispositivos CCCB
    #---------------------------------------------------------

    #if Serial.find("CCCB") != -1: #ID_Tratado = IDQ
    #    if Switch() == '1':
    #        #print 'Abierto'
    #        #borrar base de datos
    #        Borrar_BD()
    #        #print Confimacion_Firmware(Tiempo(), Leer_Archivo(17).replace('\n',''),'Abierto el dispositivo')

    #---------------------------------------------------------
    # Proceso 8: Perdida de coneccion con el Servidor
    #---------------------------------------------------------
    #Restablecer()

    #---------------------------------------------------------
    # Proceso 9: panel web
    #---------------------------------------------------------
    if (Leer_Estado(47)).find("OK") != - 1:     Resolver_Comando_Web()

    #---------------------------------------------------------
    # Proceso 10: comunicacion con el counter
    #---------------------------------------------------------
    Couter.Resolver_Comando_Counter()

    #---------------------------------------------------------
    # Proceso 10: Boton salida
    #---------------------------------------------------------
    #Boton_Salida.Eventos_Boton_Salida()
    #---------------------------------------------------------
    # Proceso 11: sensor IR y led de potencia
    #---------------------------------------------------------
    IR.Eventos_IR()
