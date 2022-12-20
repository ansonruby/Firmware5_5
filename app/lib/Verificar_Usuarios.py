#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Libreria personal para verificar usuarios segun su tipo de qr.
faltando el tipo de serie de teclas





# ideas a implementar





"""
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
from Lib_File import *  # importar con los mismos nombres
from Lib_Rout import *  # importar con los mismos nombres







#---------------------------------------------------------
#           Verificacion tipo 1             < azAZ09. azAZ09 >  -> sha256.id
#---------------------------------------------------------

def Decision_Tipo_1(QR):
    Vector = QR.split(".")
    ID = Vector[1]
    #print ID
    ID_1 = Buscar_ID_Tipo1(ID)
    #print ID_1
    if ID_1 != -1:
        #print 'verificar tipo de autorizacion'
        Pos_linea,Tipo_IO =Buscar_acceso_Tipo1(ID)
        if Pos_linea == -1 :    return -1,'Access granted-E'    # esta el usuario pero no tiene registro
        else:
            if Tipo_IO == '0':      # 0: entrada.1: salida .
                return Pos_linea,'Access granted-S'             # registro de entrada otorga salida
            elif Tipo_IO == '1':    # 0: entrada.1: salida .
                return Pos_linea,'Access granted-E'             # registro de entrada otorga Entrada

        return -1,'Denegado'
    else:
        return -1,'Denegado'

def Buscar_ID_Tipo1(ID_1):  # se puede mejorar la busqueda (busqueda binaria) si la lista esta ordenada
    Usuarios = Get_File(TAB_USER_TIPO_1)
    for linea in Usuarios.split('\n'):
        if linea.count('.') >=1:
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")
            if 	ID_1 ==	s2[0]:
                #print 'existe el usuario'
                return s2[0]
    return -1

def Buscar_acceso_Tipo1(ID_1):
    Usuarios = Get_File(TAB_AUTO_TIPO_1)
    Pos_linea=1  # comnesae en 1 para convenzar la linea cero
    for linea in Usuarios.split('\n'):
        if linea.count('.') >=1:
            #print linea
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")

            if 	ID_1 ==	s2[1]:
                #print 'existe autorizacion'
                #print linea
                                    #Datos comunes (al final de la trama)
                #print s2[2]         # time					-> tiempo en el que se realizo
                #print s2[3]         # 2: pin. 1:qr. 0: rut , 			-> tipo de dato procesado
                #print s2[4]         # 0: entrada.1: salida .
                #print s2[5]         # 1: sin Internet .  0: con Internet	-> estado de red

                #print Pos_linea

                return Pos_linea, s2[4] # retorno el estado y linea del usuarios

        Pos_linea= 1 + Pos_linea

    return -1,-1









#---------------------------------------------------------
#           Verificacion tipo 2             < azAZ09. azAZ09 >  -> sha256.id
#---------------------------------------------------------

def Decision_Tipo_2(QR):
    Vector = QR.split(".")
    ID = Vector[1]
    #print ID
    ID_1 = Buscar_ID_Tipo2(ID)
    #print ID_1
    if ID_1 != -1:
        #print 'verificar tipo de autorizacion'
        Pos_linea,Tipo_IO =Buscar_acceso_Tipo2(ID)
        if Pos_linea == -1 :    return -1,'Access granted-E'    # esta el usuario pero no tiene registro
        else:
            if Tipo_IO == '0':      # 0: entrada.1: salida .
                return Pos_linea,'Access granted-S'             # registro de entrada otorga salida
            elif Tipo_IO == '1':    # 0: entrada.1: salida .
                return Pos_linea,'Access granted-E'             # registro de entrada otorga Entrada

        return -1,'Denegado'
    else:
        return -1,'Denegado'

def Buscar_ID_Tipo2(ID_1):  # se puede mejorar la busqueda (busqueda binaria) si la lista esta ordenada
    Usuarios = Get_File(TAB_USER_TIPO_2)
    for linea in Usuarios.split('\n'):
        if linea.count('.') >=1:
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")
            if 	ID_1 ==	s2[0]:
                #print 'existe el usuario'
                return s2[0]
    return -1

def Buscar_acceso_Tipo2(ID_1):
    Usuarios = Get_File(TAB_AUTO_TIPO_2)
    Pos_linea=1  # comnesae en 1 para convenzar la linea cero
    for linea in Usuarios.split('\n'):
        if linea.count('.') >=1:
            #print linea
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")

            if 	ID_1 ==	s2[1]:
                #print 'existe autorizacion'
                #print linea
                                    #Datos comunes (al final de la trama)
                #print s2[2]         # time					-> tiempo en el que se realizo
                #print s2[3]         # 2: pin. 1:qr. 0: rut , 			-> tipo de dato procesado
                #print s2[4]         # 0: entrada.1: salida .
                #print s2[5]         # 1: sin Internet .  0: con Internet	-> estado de red

                #print Pos_linea

                return Pos_linea, s2[4] # retorno el estado y linea del usuarios

        Pos_linea= 1 + Pos_linea

    return -1,-1

def Ventana_tiempo_Tipo_2(QR, Tiempo_Actual, Resp):
    #-------  ventana de tiempo 60 minutos
    Vector = QR.split(".")
    Tiempo_inicio = int(float(Vector[2])/1000)
    T_A           = int(float(Tiempo_Actual)/1000)
    Tiempo_fin    = int(float(Vector[2])/1000) + (900*4)  # 900 = 15   -> 60 mimutos 900*4
    #print 'T inicio:' + str( datetime.datetime.fromtimestamp(Tiempo_inicio))
    #print 'T Actual:' + str( datetime.datetime.fromtimestamp(T_A))
    #print 'T Fin   :' + str( datetime.datetime.fromtimestamp(Tiempo_fin))
    if (Tiempo_inicio <= T_A) and (T_A <= Tiempo_fin):
        return 1
    else:
        if Resp =='Access granted-S':   return 1 # si no a salido, dejarlo salir
        else:                           return -1








#---------------------------------------------------------
#           Verificacion tipo 2_1   < azAZ09. azAZ09. 09. 09 >    -> sha256.id.tiempo init.tiempo fin.
#---------------------------------------------------------

def Decision_Tipo_2_1(QR):
    Vector = QR.split(".")
    ID = Vector[1]
    #print ID
    ID_1 = Buscar_ID_Tipo2_1(ID)
    #print ID_1
    if ID_1 != -1:
        #print 'verificar tipo de autorizacion'
        Pos_linea,Tipo_IO =Buscar_acceso_Tipo2_1(ID)
        #print Tipo_IO
        if Pos_linea == -1 :    return -1,'Access granted-E'    # esta el usuario pero no tiene registro
        else:
            if Tipo_IO == '0':      # 0: entrada.1: salida .
                return Pos_linea,'Access granted-S'             # registro de entrada otorga salida
            elif Tipo_IO == '1':    # 0: entrada.1: salida .
                return Pos_linea,'Access granted-E'             # registro de entrada otorga Entrada

        return -1,'Denegado'
    else:
        return -1,'Denegado'

def Buscar_ID_Tipo2_1(ID_1):  # se puede mejorar la busqueda (busqueda binaria) si la lista esta ordenada
    Usuarios = Get_File(TAB_USER_TIPO_2_1)
    for linea in Usuarios.split('\n'):
        if linea.count('.') >=1:
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")
            if 	ID_1 ==	s2[0]:
                #print 'existe el usuario'
                return s2[0]
    return -1

def Buscar_acceso_Tipo2_1(ID_1):
    Usuarios = Get_File(TAB_AUTO_TIPO_2_1)
    Pos_linea=1  # comnesae en 1 para convenzar la linea cero
    for linea in Usuarios.split('\n'):
        if linea.count('.') >=1:
            #print linea
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")
            #print s2[1]
            if 	ID_1 ==	s2[1]:
                #print 'existe autorizacion'
                #print linea
                                    #Datos comunes (al final de la trama)
                #print s2[2]         # time					-> tiempo en el que se realizo
                #print s2[3]         # 2: pin. 1:qr. 0: rut , 			-> tipo de dato procesado
                #print s2[4]         # 0: entrada.1: salida .
                #print s2[5]         # 1: sin Internet .  0: con Internet	-> estado de red

                #print Pos_linea

                return Pos_linea, s2[6] # retorno el estado y linea del usuarios

        Pos_linea= 1 + Pos_linea

    return -1,-1

def Ventana_tiempo_Tipo_2_1(QR, Tiempo_Actual, Resp):
    Vector = QR.split(".")
    Tiempo_inicio = int(float(Vector[2])/1000)
    T_A           = int(float(Tiempo_Actual)/1000)
    Tiempo_fin    = int(float(Vector[3])/1000)
    #print 'T inicio:' + str( datetime.datetime.fromtimestamp(Tiempo_inicio))
    #print 'T Actual:' + str( datetime.datetime.fromtimestamp(T_A))
    #print 'T Fin   :' + str( datetime.datetime.fromtimestamp(Tiempo_fin))
    if (Tiempo_inicio <= T_A) and (T_A <= Tiempo_fin):
        return 1
    else:
        if Resp =='Access granted-S':   return 1 # si no a salido, dejarlo salir
        else:                           return -1









#---------------------------------------------------------
#           Verificacion tipo 3   09. azAZ09. azAZ09. azAZ09. 09  -> tipo.id.id.id.tiempo init.   tiken un solo uso
#---------------------------------------------------------

def Decision_Tipo_3(QR):
    Vector = QR.split(".")
    tipo_QR = Vector[0]
    if tipo_QR =='3':
        ID =  Vector[1] + '.' + Vector[2]+ '.' + Vector[3]
        #print ID
        Pos_L,Max_In,Actuales_In = Buscar_ID_Tipo3(ID)
        #print Pos_L
        #print Max_In
        #print Actuales_In
        #print 'incremento'
        Incre = int(Actuales_In)+1
        #print Incre

        if Pos_L != -1:
            #print 'verificar contidad de autorizaciones autorizacion'
            if Actuales_In < Max_In:    return Pos_L,'Access granted-E',str(Incre)
            else:                       return -1,'Denegado',-1

        else:
            return -1,'Denegado',-1
    else:
        return -1,'Denegado',-1

def Buscar_ID_Tipo3(ID_1):  # se puede mejorar la busqueda (busqueda binaria) si la lista esta ordenada
    Pos_linea=1  # comnesae en 1 para convenzar la linea cero
    Usuarios = Get_File(TAB_USER_TIPO_3)
    for linea in Usuarios.split('\n'):
        if linea.count('.') >=1:
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")
            ID =  s2[0] + '.' + s2[1]+ '.' + s2[2]
            if 	ID_1 ==	ID:
                #print 'existe el usuario'
                #print s2[2]
                #print s2[3]
                return Pos_linea, s2[2], s2[3]

            Pos_linea= 1 + Pos_linea

    return -1,-1,-1

def Buscar_acceso_Tipo3(ID_1):
    Usuarios = Get_File(TAB_AUTO_TIPO_3)
    Pos_linea=1  # comnesae en 1 para convenzar la linea cero
    for linea in Usuarios.split('\n'):
        if linea.count('.') >=1:
            #print linea
            s=linea.rstrip('\n')
            s=s.rstrip('\r')
            s2 =s.split(".")
            ID =  s2[1] + '.' + s2[2]+ '.' + s2[3]
            if 	ID_1 ==	ID:
                #print 'existe autorizacion'
                #print linea
                                    #Datos comunes (al final de la trama)
                #print s2[2]         # time					-> tiempo en el que se realizo
                #print s2[3]         # 2: pin. 1:qr. 0: rut , 			-> tipo de dato procesado
                #print s2[4]         # 0: entrada.1: salida .
                #print s2[5]         # 1: sin Internet .  0: con Internet	-> estado de red

                #print Pos_linea

                return Pos_linea, s2[7] # retorno el estado y linea del usuarios

        Pos_linea= 1 + Pos_linea

    return -1,-1

def Ventana_tiempo_Tipo_3(QR, Tiempo_Actual, Resp):
    Vector = QR.split(".")

    T_inicio = int(Vector[4])
    #inicio = str(T_inicio)
    #fin = str(int(SQR[3]))
    #print 'T inicio:' + inicio
    #print 'T Actual: ', str(T_A)

    #quemar 60 minutos   3600 segundos

    if Tiempo_Actual > T_inicio :
        Resta = (int(Tiempo_Actual) -int(Vector[4]))/1000
        if Resta >=3600 :
            print 'vencido'
            #Decision_Torniquete ('Denegar',QR,"",T_A,'1','1')
            return -1
        else:
            print 'dentro'
            return 1

    """
    Tiempo_inicio = int(float(Vector[2])/1000)
    T_A           = int(float(Tiempo_Actual)/1000)
    Tiempo_fin    = int(float(Vector[3])/1000)
    #print 'T inicio:' + str( datetime.datetime.fromtimestamp(Tiempo_inicio))
    #print 'T Actual:' + str( datetime.datetime.fromtimestamp(T_A))
    #print 'T Fin   :' + str( datetime.datetime.fromtimestamp(Tiempo_fin))
    if (Tiempo_inicio <= T_A) and (T_A <= Tiempo_fin):
        return 1
    else:
        if Resp =='Access granted-S':   return 1 # si no a salido, dejarlo salir
        else:                           return -1
    """
