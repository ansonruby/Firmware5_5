from crontab import CronTab

def Crear_Trabajo (Trabajo, ID):
    my_cron = CronTab(user = 'pi')
    job = my_cron.new(command= Trabajo, comment=ID)
    job.every_reboot()
    my_cron.write()

def Eliminar_Trabajo (ID):
    my_cron = CronTab(user = 'pi')
    for job in my_cron:
        if job.comment == ID:
            #print job
            my_cron.remove(job)     #eliminar una tarea
            my_cron.write()
            return 'OK'
    return 'NO'

def Desactivar_Trabajo (ID):
    my_cron = CronTab(user = 'pi')
    #my_cron = CronTab(user = True)
    for job in my_cron:
        if job.comment == ID:
            #print job
            job.enable(False)      #desactivar tarea
            my_cron.write()
            return 'OK'
    return 'NO'

def Activar_Trabajo (ID):
    my_cron = CronTab(user = 'pi')
    for job in my_cron:
        if job.comment == ID:
            #print job
            job.enable()           #activar tarea
            my_cron.write()
            return 'OK'
    return 'NO'

def Desactivar_Trabajos (res16):

    #res16 = Leer_Archivo(16) # procesos automaticos

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
            print Desactivar_Trabajo(ID)


def Activar_Trabajos (res16):

    #res16 = Leer_Archivo(16) # procesos automaticos

    Trabajos =res16.split("\n")

    for Trabajo in range(len(Trabajos)):
        c = Trabajos[Trabajo]
        print c
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
        print Activar_Trabajo(ID)

def Adicionar_Trabajos(res16):
    #res16 = Leer_Archivo(16) # procesos automaticos

    Trabajos =res16.split("\n")

    for Trabajo in range(len(Trabajos)):
        c = Trabajos[Trabajo]
        print c
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

def Eliminar_Trabajos (res16):
    #res16 = Leer_Archivo(16) # procesos automaticos

    Trabajos =res16.split("\n")

    for Trabajo in range(len(Trabajos)):
        c = Trabajos[Trabajo]
        print c
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
        print Eliminar_Trabajo(ID)
