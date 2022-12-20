import commands
import sys
import time

from crontab import CronTab

import lib.Control_Archivos2  as Ca
import lib.Control_Automatico  as Cu

#-----------------------------------
#           Definiciones
#-----------------------------------

Leer		        = Ca.Leer_Led
Borrar		        = Ca.Borrar_Archivo
Escrivir_Estados        = Ca.Escrivir_Estados
Escrivir                = Ca.Escrivir_Archivo
Leer_Estado             = Ca.Leer_Estado
Leer_Archivo            = Ca.Leer_Archivo
Generar		            = Ca.Generar_ID_Tarjeta

Crear_Trabajo           = Cu.Crear_Trabajo
Eliminar_Trabajo        = Cu.Eliminar_Trabajo
Activar_Trabajo         = Cu.Activar_Trabajo
Desactivar_Trabajo      = Cu.Desactivar_Trabajo

# ------------------------------
#           Constantes
# ------------------------------
MAC_DIRC        = 'cat /sys/class/net/eth0/address'
MAC_DIRC        = 'cat /sys/class/net/wlan0/address'
MAC             = commands.getoutput(MAC_DIRC)
MAC             = MAC.replace(":","")
ID_Tarjeta      = Generar(MAC)
#ID_Tarjeta      = ID_Tarjeta +'5'
# para Clonar repositorios
Direccion_Clonada           = ' /home/pi/Actualizador/'
Nombre_Carpeta_clonada      = 'Nueva_Actualizacion'
Direccion_Firmware          = ' /home/pi/'
Nombre_Carpeta_Firmware     = 'Firmware'
GIT                         = ''

#print ID_Tarjeta       #ID tarjeta mejorar que quede una sola peticion
# ejemplo de comandos
#res2 = commands.getoutput('ifconfig')
#print res2

timpoespera = 1

# ------------------------------
#       Funciones
# ------------------------------
def Estatus_Coneccion (c):
        res2 = commands.getoutput('cat /sys/class/net/'+c+'/carrier')
        if res2 == '0':     return 0 #  print 'Desconectado'
        else:               return 1 # print 'Conectado'
#-----------------------------------------------
def Estados_Internet():
        Sres = ""
        Cantidad =0
        res = commands.getoutput('ls /sys/class/net/')
        redes =res.split("\n")
        Conectado = 0;

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
                            Conectado = 1;
                if c.find('wlan') != -1: #print 'Wifi'

                        if Estatus_Coneccion (c) == 0:  #print 'WD'
                                Sres = Sres + 'WD'
                                Cantidad+=1
                        else:                           #print 'WC'
                                Sres = Sres + 'WC'
                                Cantidad+=1
                                Conectado = 1;
        #print str(Cantidad) + Sres
        #return  str(Cantidad) + Sres
        return Conectado
#-----------------------------------------------
def Verificar_Actualizacion (Arc): #archivo de la peticion que llego

    lineas =Arc.split("\n")     #separador

    for linea in range(len(lineas)):
        c = lineas[linea]
        #print c
        if linea == 0 :
            if ID_Tarjeta !=  c :
                print 'NO es para mi'
                return '0'
        if linea == 1 :
            if Leer_Archivo(17) ==  c :
                print 'ya esta actualizado'
                return '1'
        if linea == 2 :
            print 'Devo actualizar'
            return c
#-----------------------------------------------
def adicionar_Trabajos():
    res16 = Leer_Archivo(16) # procesos automaticos

    Trabajos =res16.split("\n")

    for Trabajo in range(len(Trabajos)):
        c = Trabajos[Trabajo]
        print c
        print len (c)
        if len(c) >=1:
            c2 =c.split(")")
            c3 =c2[0].split("(")

            if c3[0][0] == '#': print  'Desabilitado'
            else :              print  'Abilitado'
            if c3[0].find('reboot') != -1 :     print 'desde el inico'
            else :                              print 'Otra configuracion'

            comando = "(" + c3[1] + ")"
            print 'comando: ' + comando
            ID = c2[1].replace(" ","")
            ID = ID.replace("#","")
            print 'ID: ' + ID

            Crear_Trabajo(comando,ID)
#-----------------------------------------------
def eliminar_trabajos ():

    res16 = Leer_Archivo(16) # procesos automaticos

    Trabajos =res16.split("\n")

    for Trabajo in range(len(Trabajos)):
        c = Trabajos[Trabajo]
        print c
        print len (c)
        if len(c) >=1:
            c2 =c.split(")")
            c3 =c2[0].split("(")

            if c3[0][0] == '#': print  'Desabilitado'
            else :              print  'Abilitado'
            if c3[0].find('reboot') != -1 :     print 'desde el inico'
            else :                              print 'Otra configuracion'

            comando = "(" + c3[1] + ")"
            print 'comando: ' + comando
            ID = c2[1].replace(" ","")
            ID = ID.replace("#","")
            print 'ID: ' + ID

            #Crear_Trabajo(comando,ID)
            Eliminar_Trabajo(ID)
#-----------------------------------------------
def desactivar_trabajos ():

    res16 = Leer_Archivo(16) # procesos automaticos

    Trabajos =res16.split("\n")

    for Trabajo in range(len(Trabajos)):
        c = Trabajos[Trabajo]
        print c
        print len (c)
        if len(c) >=1:
            c2 =c.split(")")
            c3 =c2[0].split("(")

            if c3[0][0] == '#': print  'Desabilitado'
            else :              print  'Abilitado'
            if c3[0].find('reboot') != -1 :     print 'desde el inico'
            else :                              print 'Otra configuracion'

            comando = "(" + c3[1] + ")"
            print 'comando: ' + comando
            ID = c2[1].replace(" ","")
            ID = ID.replace("#","")
            print 'ID: ' + ID

            #Crear_Trabajo(comando,ID)
            Desactivar_Trabajo(ID)
#-----------------------------------------------
def activar_trabajos ():

    res16 = Leer_Archivo(16) # procesos automaticos

    Trabajos =res16.split("\n")

    for Trabajo in range(len(Trabajos)):
        c = Trabajos[Trabajo]
        print c
        print len (c)
        if len(c) >=1:
            c2 =c.split(")")
            c3 =c2[0].split("(")

            if c3[0][0] == '#': print  'Desabilitado'
            else :              print  'Abilitado'
            if c3[0].find('reboot') != -1 :     print 'desde el inico'
            else :                              print 'Otra configuracion'
            comando = "(" + c3[1] + ")"
            print 'comando: ' + comando
            ID = c2[1].replace(" ","")
            ID = ID.replace("#","")
            print 'ID: ' + ID

            #Crear_Trabajo(comando,ID)
            Activar_Trabajo(ID)
#-----------------------------------------------
def Log_Actualizador(Dato):
    print Dato
    Escrivir(Dato,19)
#-----------------------------------------------
def Ultimo_estado():

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

        return Ultimo

    else :
        return -1

    return -2
#-----------------------------------------------
def Etapa_1():
    global Direccion_Clonada
    global Nombre_Carpeta_clonada

    # 1. Eliminar carpeta anteriores clonaciones
    Log_Actualizador('1. Eliminar Archivos.')
    Log_Actualizador('1.1 Eliminar anteriores clonaciones.')
    res = commands.getoutput('sudo rm -R' + Direccion_Clonada+ Nombre_Carpeta_clonada)
    print 'Respuesta:'+ res
#-----------------------------------------------
def Etapa_2():
    global GIT
    global Direccion_Clonada
    global Nombre_Carpeta_clonada

    res = ""

    if Estados_Internet() == 1:
        Log_Actualizador('2. Clonar repositorio')
        print 'clonando'
        res = commands.getoutput('git clone ' + GIT + Direccion_Clonada+ Nombre_Carpeta_clonada)
        print 'Respuesta:'+ res

        res = commands.getoutput('[ -d /home/pi/Actualizador/Nueva_Actualizacion ] && echo "Existe" || echo "NO_existe"')
        print 'Respuesta:'+ res

        if res == 'NO_existe':
            print "No Clone"
            Log_Actualizador('2. Clonar repositorio, Error NO Clone')
            Escrivir_Estados('4',20)
            commands.getoutput('sudo reboot')

    else :
        print "No hay Internet"
        Log_Actualizador('2. Clonar repositorio, Error NO hay Internet')
        Escrivir_Estados('4',20)
        commands.getoutput('sudo reboot')


    print 'Respuesta:'+ res
#-----------------------------------------------
def Etapa_3():
    Log_Actualizador('3. Verificar repositorio MD5 o listado de lo que viene')

    res = commands.getoutput('[ -d /home/pi/Actualizador/Nueva_Actualizacion ] && echo "Existe" || echo "NO_existe"')
    print 'Nueva_Actualizacion:'+res
    if res == 'NO_existe':
            print "No Nueva_Actualizacion"
            Log_Actualizador('3. Verificar repositorio, Error No hay Carpeta Nueva_Actualizacion')
            Escrivir_Estados('4',20)
            commands.getoutput('sudo reboot')
    res = commands.getoutput('[ -d /home/pi/Actualizador/Nueva_Actualizacion/Actualizador ] && echo "Existe" || echo "NO_existe"')
    print 'Actualizador:'+res
    if res == 'NO_existe':
            print "No Actualizador"
            Log_Actualizador('3. Verificar repositorio, Error No hay Carpeta Actualizador')
            Escrivir_Estados('4',20)
            commands.getoutput('sudo reboot')
    res = commands.getoutput('[ -d /home/pi/Actualizador/Nueva_Actualizacion/app ] && echo "Existe" || echo "NO_existe"')
    print 'app:'+res
    if res == 'NO_existe':
            print "No app"
            Log_Actualizador('3. Verificar repositorio, Error No hay Carpeta app')
            Escrivir_Estados('4',20)
            commands.getoutput('sudo reboot')
    res = commands.getoutput('[ -d /home/pi/Actualizador/Nueva_Actualizacion/auto ] && echo "Existe" || echo "NO_existe"')
    print 'auto:'+res
    if res == 'NO_existe':
            print "No auto"
            Log_Actualizador('3. Verificar repositorio, Error No hay Carpeta auto')
            Escrivir_Estados('4',20)
            commands.getoutput('sudo reboot')
    res = commands.getoutput('[ -d /home/pi/Actualizador/Nueva_Actualizacion/img ] && echo "Existe" || echo "NO_existe"')
    print 'img:'+res
    if res == 'NO_existe':
            print "No img"
            Log_Actualizador('3. Verificar repositorio, Error No hay Carpeta img')
            Escrivir_Estados('4',20)
            commands.getoutput('sudo reboot')
    res = commands.getoutput('[ -d /home/pi/Actualizador/Nueva_Actualizacion/sh ] && echo "Existe" || echo "NO_existe"')
    print 'sh:'+res
    if res == 'NO_existe':
            print "No sh"
            Log_Actualizador('3. Verificar repositorio, Error No hay Carpeta sh')
            Escrivir_Estados('4',20)
            commands.getoutput('sudo reboot')

    res = 'No implementado'
    print res
#-----------------------------------------------
def Etapa_4():
    global Direccion_Firmware
    global Nombre_Carpeta_Firmware

    Log_Actualizador('4. Cambiar nombre de firmware en ejecucion')
    res = commands.getoutput('[ ! -f /home/pi/FirmwareBK ] && echo "Existe" || echo "NO exiete"')
    if res == 'Existe':
        print 'Eliminar BK'
        res = commands.getoutput('sudo rm -R' + ' /home/pi/FirmwareBK')
        print res

    res = commands.getoutput('mv' + Direccion_Firmware + Nombre_Carpeta_Firmware + Direccion_Firmware + Nombre_Carpeta_Firmware + 'BK')
    print 'Respuesta:'+ res
#-----------------------------------------------
def Etapa_5():
    global Direccion_Clonada
    global Nombre_Carpeta_clonada
    global Direccion_Firmware
    global Nombre_Carpeta_Firmware

    Log_Actualizador('5. Copiar carpeta Clonada y cambio de nombre a nombre del firmware')
    #print 'cp -r' + Direccion_Clonada+ Nombre_Carpeta_clonada + Direccion_Firmware+ Nombre_Carpeta_Firmware
    res = commands.getoutput('cp -r' + Direccion_Clonada+ Nombre_Carpeta_clonada + Direccion_Firmware+ Nombre_Carpeta_Firmware)
    print 'Respuesta:'+ res
#-----------------------------------------------
def Etapa_6():

    Log_Actualizador('6. Modificar procesos automaticos')
    Log_Actualizador('6.1 Eliminar Trabajos')       # memoria del proceso
    eliminar_trabajos()                             # revisar proceos anteriores 18 archivo
    Log_Actualizador('6.2 Adicionar Trabajos')      # memoria del proceso
    adicionar_Trabajos()                            # procesos actuales
#-----------------------------------------------
def Etapa_7():

    Log_Actualizador('7. permisos de ejecucion de archivos .sh')    #memoria del proceso

    res = commands.getoutput('ls /home/pi/Firmware/sh/')
    shs =res.split("\n")
    print res
    for linea in range(len(shs)):
        c = shs[linea]
        print 'chmod -R 755 /home/pi/Firmware/sh/'+c
        res = commands.getoutput('chmod -R 755 /home/pi/Firmware/sh/'+c)
        print 'Respuesta:'+ res
        #Escrivir(res,19)    #memoria del proceso
#-----------------------------------------------
def Etapa_8():
    Log_Actualizador('8. Reiniciar dispostivo.')
    #print 'No implementado'
    commands.getoutput('sudo reboot')
#-----------------------------------------------
def Etapa_9():

    Log_Actualizador('9. verificar si estan en funcionamiento los procesos')
    #print 'No implementado'
    # posiblemente se coloque un proceso de verificacion de ejecucion de crontab -e
    # se requiere un proceso que verifique el funcionamiento
    # y una memoria que sepa enque estado va el proceso
    # arancando un proceos de nuevo
    # nohup  python /home/pi/Firmware/app/Chicharra.py

    res16 = Leer_Archivo(16) # procesos automaticos

    Trabajos =res16.split("\n")

    Cantidad_Trabajos = len(Trabajos)
    print 'Cantidad de Trabajos :' +str(Cantidad_Trabajos)

    C_Trabajos = 0

    for Trabajo in range(Cantidad_Trabajos):
        c = Trabajos[Trabajo]
        print c
        print len (c)
        if len(c) >=1 :
            c2 =c.split(")")
            c3 =c2[0].split("(")

            #if c3[0][0] == '#': print  'Desabilitado'
            #else :              print  'Abilitado'
            #if c3[0].find('reboot') != -1 :     print 'desde el inico'
            #else :                              print 'Otra configuracion'

            comando = "(" + c3[1] + ")"
            #print 'comando: ' + comando
            ID = c2[1].replace(" ","")
            ID = ID.replace("#","")
            #print 'ID: ' + ID
            res = commands.getoutput('ps aux | grep '+ID)
            #print 'Respuesta:'+ res
            C_procesos=0
            Procesos = res.split("\n")
            for Proceso in range(len(Procesos)):

                c = Procesos[Proceso]
                #print c
                if c.find('grep') == -1 : # filtro de procesos
                    #print c
                    if c.find('python') != -1 :
                        #print 'funcionando'
                        C_procesos = C_procesos +1
                        #print C_procesos


            if C_procesos >= 1: # revisar cuanto generera par comparar correctamente
                print 'funcionando: '+ ID + ' ' + str(C_procesos)
                C_Trabajos = C_Trabajos + 1
            else:
                print 'NO fun: '+ ID + ' ' + str(C_procesos)

    print  C_Trabajos
    if C_Trabajos == Cantidad_Trabajos:
        print  'funciona bien los trabajos'
        #Escrivir('funciona bien los trabajos',19)
    else :
        #Escrivir('Hay trabajos que no se ejecutaron',19)
        print 'Hay trabajos que no se ejecutaron'
#-----------------------------------------------
def Etapa_10():
    #   mejortar el borradode de los archivos
    #   se deve nmmatener los datos que se estaba procesando antes de resivir la actializacion
    #
    #   rm -r /home/pi/Firmware/db/Data/*.txt
    print '10. colocar de fabrica el dispostivo'
    #por defecto deve venir pero porsi
    #print 'No implementado'
    """
    Borrar(0)       #borrar tabla servidor
    Borrar(1)       #borrar tabla lector
    Borrar(2)       #borrar tabla Enviar
    print 'Base datos borrado'

    #Borrar(12)       #Borrar Numero de lecturas
    #Escrivir('0',12) #dejar en 0 las lecturas

    Borrar(14)       #Borrar Numero de Reinicios
    Escrivir('0',14) #dejar en 0 los reinicios
    print 'Historial borrado'

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
    """
#-----------------------------------------------
def Etapa_11():

    print '11. Colocar configuraciones y datos que no a procesado el servidor'
    print 'No implementado'
#-----------------------------------------------
def Etapa_12():

    Log_Actualizador('12. Reinicio adicional para eliminar procesos de verificacion.')
    Log_Actualizador('12.1 Activar procesos.')
    activar_trabajos()
    Log_Actualizador('12.2 Dezavilitar procesos Actualizacion.')
    Desactivar_Trabajo('Actualizador')
    Desactivar_Trabajo('Proceso_Actualizar')
    Log_Actualizador('12.3 Reiniciar dispostivo.')
    Borrar(15)      #Borrar peticion concluida
    Escrivir_Estados('3',20)

    commands.getoutput('sudo reboot')
#-----------------------------------------------
def Etapa_13():

    print '13. Respuesta al servidor del proceso de actualizacion'
    print 'No implementado'
#-----------------------------------------------
def Etapa_14():

    print '14. Estado Normal de funcionamiento'
    print 'No implementado'
#-----------------------------------------------

# ------------------------------
#       Funcion principal
# ------------------------------


#-----  simulacion de respuesta de Actualizacion

# -2. peticion de actualizacion:
#           datos de envio del dispostivo al servidor para actualizacion:
#           ID_Dispostivo, Vercion_actual_firware.
#       respuesta de la peticion

# ---------
# verificar el proceso de Atualizacion
# --------

def Comienso_04():
    global timpoespera
    print 'comensar desde aqui'
    Etapa_1()
    time.sleep(timpoespera)
    Etapa_2()
    time.sleep(timpoespera)
    Etapa_3()
    time.sleep(timpoespera)
    Etapa_4()
    time.sleep(timpoespera)
    Etapa_5()
    time.sleep(timpoespera)
    Etapa_6()
    time.sleep(timpoespera)
    Etapa_7()
    time.sleep(timpoespera)
    Etapa_8()

def Comienso_8():
    global timpoespera
    print 'comensar desde aqui'
    Etapa_9()
    time.sleep(timpoespera)
    Etapa_10()
    time.sleep(timpoespera)
    Etapa_11()
    time.sleep(timpoespera)
    Etapa_12()



def Volver_Firmware_Anterior():

    # volver pasoos si exsite un bk del firmares
    res = commands.getoutput('[ ! -f /home/pi/FirmwareBK ] && echo "Existe" || echo "NO existe"')
    if res == 'Existe':
        res = commands.getoutput('[ ! -f /home/pi/Firmware ] && echo "Existe" || echo "NO existe"')
        if res == 'Existe':

            #Log_Actualizador('6.1 Eliminar Trabajos')       # memoria del proceso
            eliminar_trabajos()
            #print 'Eliminar Firmware'
            res = commands.getoutput('sudo rm -R' + ' /home/pi/Firmware')
            print res
        #Bk firmware restaurado
        res = commands.getoutput('mv /home/pi/FirmwareBK /home/pi/Firmware')
        #Log_Actualizador('6.2 Adicionar Trabajos')      # memoria del proceso
        adicionar_Trabajos()

        #Log_Actualizador('7. permisos de ejecucion de archivos .sh')    #memoria del proceso
        res = commands.getoutput('ls /home/pi/Firmware/sh/')
        shs =res.split("\n")
        print res
        for linea in range(len(shs)):
            c = shs[linea]
            print 'chmod -R 755 /home/pi/Firmware/sh/'+c
            res = commands.getoutput('chmod -R 755 /home/pi/Firmware/sh/'+c)
            print 'Respuesta:'+ res

    Escrivir_Estados('4',20)
    commands.getoutput('sudo reboot')
            #Escrivir(res,19)    #memoria del proceso
    #devolver el actualizador o clocar el que tien este firware

    """
    res = commands.getoutput('[ ! -f /home/pi/ActualizadorBK ] && echo "Existe" || echo "NO existe"')
    if res == 'Existe':
        res = commands.getoutput('[ ! -f /home/pi/Actualizador ] && echo "Existe" || echo "NO existe"')
        if res == 'Existe':
            print 'Eliminar Actualizador'
            res = commands.getoutput('sudo rm -R' + ' /home/pi/Actualizador')
            print res

        res = commands.getoutput('mv /home/pi/ActualizadorBK /home/pi/Actualizador')

    """
    #res = commands.getoutput('mv /home/pi/Actualizador /home/pi/ActualizadorBK')
    #res = commands.getoutput('cp -r /home/pi/Firmware/Actualizador /home/pi/Actualizador')
    #res = commands.getoutput('chmod -R 755 /home/pi/Actualizador/sh/app_Actualizando.sh')
    #print 'Respuesta:'+ res


def Proceso_Actualizador():
    global GIT
    Arc = Leer_Archivo(15)

    print Arc
    lineas =Arc.split("\n")

    GIT = lineas[2]
    print GIT


    Estado_Proceso_Actualizador = Ultimo_estado()
    print Estado_Proceso_Actualizador



    if Estado_Proceso_Actualizador == -1:
        print 'el archivo esta vacio'
    elif Estado_Proceso_Actualizador == '0.':
        print 'Comienso actualizacion'
    elif  Estado_Proceso_Actualizador == "0.4" :
        print 'Comienso actualizacion corecta'
        Comienso_04()
    elif  Estado_Proceso_Actualizador == "8." :
        print 'Comienso actualizacion corecta'
        Comienso_8()
    elif  Estado_Proceso_Actualizador == "12.3" :
        print 'Comienso actualizacion corecta'
    else :
        print "Error Actualizando"
        #Volver_Firmware_Anterior()


    """
    if Resp == '1':
        print 'Verificar procesoa activos y desactivar los de actualizacion'
    else:
        print "No deveria estar en este estado"
        # deve verificar si termino de actualizar
        # verificar que esta funcionado o no
        #remediar la  situacion
        # dejar en funvionamiento normal
    """


Proceso_Actualizador()
"""
Arc = Leer_Archivo(15)
print Arc
lineas =Arc.split("\n")
GIT = lineas[2]
print GIT

Etapa_2()
"""
#Etapa_5()
"""
while 1:
    print Estados_Internet()
    time.sleep(2.05)
"""
