

from turtle import Turtle
import commands
import socket
import fcntl
import struct
import time
import requests


from lib.Lib_File import *  # importar con los mismos nombres
from lib.Lib_Rout import *  # importar con los mismos nombres

# ----------------------------------------------
#                   Funciones
# ----------------------------------------------


def add_Tipos_Usuarios_Nuevos(Usuario):

    puntos = Usuario.count(".")

    # print 'Puntas_separacion: ' + str(puntos)
    # -----------------------------------------------------------------------------------------
    #           Formato 1 :         azAZ09. azAZ09                  -> sha256.id  si exite el ID entra
    # -----------------------------------------------------------------------------------------

    if puntos == 1:
        # print '-----Formato 1: azAZ09. azAZ09 '
        Add_File(TAB_USER_TIPO_1, Usuario+'\n')
        Add_File(TAB_USER_TIPO_2, Usuario+'\n')
        Add_File(TAB_USER_TIPO_2_1, Usuario+'\n')
        # print 'Nuevo'

    # -----------------------------------------------------------------------------------------
    #           Formato 2 :         azAZ09. azAZ09. 09              -> sha256.id.tiempo ventana quemado 60 minutos
    # -----------------------------------------------------------------------------------------

    # -----------------------------------------------------------------------------------------
    #           Formato 2.1 :       azAZ09. azAZ09. 09. 09          -> sha256.id.tiempo init.tiempo fin.
    # -----------------------------------------------------------------------------------------
    elif puntos == 2: #para sin tipo
        # print '-----Formato 6: 6. azAZ09. azAZ09. 09'
        s2 = Usuario.split(".")
        ID = s2[1] + '.' + s2[2] + '.' + '11' #s2[3]
        Add_File(TAB_USER_TIPO_6, ID+'\n')
        #Clear_File(TAB_USER_TIPO_6)
        #Clear_File(TAB_AUTO_TIPO_6)

    elif puntos == 4:
        # print '-----Formato 3: azAZ09. azAZ09. 09. 09'
        s2 = Usuario.split(".")
        ID = s2[1] + '.' + s2[2] + '.' + s2[3] + '.' + s2[4]
        Add_File(TAB_USER_TIPO_3, ID+'\n')
        # add_New_Tikecket(Usuario)


    # -----------------------------------------------------------------------------------------
    #           Formato 3 :         09. azAZ09. azAZ09. azAZ09. 09  -> tipo.id.id.id.tiempo init.   tiken un solo uso
    # -----------------------------------------------------------------------------------------
    else:
        print '-----Formato : no definido'


# se puede mejorar la busqueda (busqueda binaria) si la lista esta ordenada
def Buscar_ID_Tipo3(ID_1):
    Usuarios = Get_File(TAB_USER_TIPO_3)
    for linea in Usuarios.split('\n'):
        if linea.count('.') >= 1:
            s = linea.rstrip('\n')
            s = s.rstrip('\r')
            s2 = s.split(".")
            ID = s2[0] + '.' + s2[1] + '.' + s2[2]
            if ID_1 == ID:
                print 'existe el usuario'
                return ID
    return -1


def add_Autorizados_Tikecket(usuario):

    puntos = usuario.count(".")

    if puntos == 9:

        print usuario
        Add_File(TAB_AUTO_TIPO_3, usuario+'\n')
        print 'Nuevo'
    else:
        print 'No cumple parametros'


def update_or_delete_Ticket(usuario):

    puntos = usuario.count(".")

    if puntos == 9:
        s = usuario.split(".")
        ID_1 = s[1] + '.' + s[2] + '.' + s[3]
        Usuarios = Get_File(TAB_USER_TIPO_3)
        newUsuarios = ""
        isFirst=True
        for linea in Usuarios.split('\n'):
            if linea.count('.') >= 1:
                ticket = linea.rstrip('\n')
                ticket = ticket.rstrip('\r')
                s2 = ticket.split(".")
                ID = s2[0] + '.' + s2[1] + '.' + s2[2]
                if ID_1 == ID and isFirst:
                    if(int(s[-1])<int(s[3])):
                        newUsuarios += s[1] + '.' + s[2] + '.' + s[3] + '.' + s[-1] + "\n"
                    isFirst=False
                else:
                    newUsuarios += linea + "\n"
        Clear_File(TAB_USER_TIPO_3)
        Add_File(TAB_USER_TIPO_3, newUsuarios)

    else:
        print 'No cumple parametros'


def add_New_Tikecket(usuario):

    puntos = usuario.count(".")
    # print puntos

    if puntos == 4:
        s = usuario.split(".")
        ID = s[1] + '.' + s[2] + '.' + s[3] + '.' + s[4]
        # Respuesta = Buscar_ID_Tipo3(ID)
        # print Respuesta

        # if Respuesta == -1:
        #Comando = usuario.strip('\n')
        Add_File(TAB_USER_TIPO_3, ID+'\n')
        # print 'Usuario agregado'
        # else:
        # print 'ya existe'
    else:
        print 'No cumple parametros'


def Resolver_Comando_Counter():

    global Comando_Antes

    # print CONT_FlAG_NEW_TICKET
    # -----------------------------  Nuevos Tikecket
    flag_recived = Get_File(CONT_RECEIVED_FLAG_PATH)

    # print flag_recived

    if flag_recived == '1':
        Data = Get_File(CONT_RECEIVED_DATA_PATH)
        if Data!="" and Data!="\n":
            Split_Data = Data.split("\n")
            Header = Split_Data[0].split(".")
            # print Split_Data
            Comando = Split_Data[1:(int(Header[2])+1)]

            if Header[1] == 'newTickets':
                # -----------------------------  Aniadir nuevos tickets
                # print Comando

                # --- mejorar la validacion de campo
                if len(Comando) >= 1:
                    Usuarios = Comando
                    for linea in Usuarios:
                        s = linea.rstrip('\n')
                        if len(s) > 0:
                            # print s
                            add_New_Tikecket(s)

                Clear_File(CONT_RECEIVED_DATA_PATH)
                Clear_File(CONT_RECEIVED_FLAG_PATH)

            elif Header[1] == 'delTickets':
                # -----------------------------  Eliminar Autorizados

                # --- mejorar la validacion de campo
                if len(Comando) >= 1:
                    Usuarios = Comando
                    for linea in Usuarios:
                        s = linea.rstrip('\n')
                        if len(s) > 0:
                            # print s
                            add_Autorizados_Tikecket(s)
                            update_or_delete_Ticket(s)

                #Add_File(TAB_LECTOR, Comando)

                Clear_File(CONT_RECEIVED_DATA_PATH)
                Clear_File(CONT_RECEIVED_FLAG_PATH)

            elif Header[1] == 'currentTickets':
                # -----------------------------  Actualizar Usuarios ----

                # print 'Actualizar Usuarios'

                # print Comando
                # --- mejorar la validacion de campo
                # antes de borrar tab berificar si hay usuaior corectos nuevos
                # Clear_File(TAB_SERVER)
                #           ------  borrado de todos los usuarios
                Clear_File(TAB_USER_TIPO_1)
                Clear_File(TAB_AUTO_TIPO_1)
                Clear_File(TAB_PINES_TIPO_1)
                Clear_File(TAB_USER_TIPO_2)
                Clear_File(TAB_AUTO_TIPO_2)
                Clear_File(TAB_USER_TIPO_2_1)
                Clear_File(TAB_AUTO_TIPO_2_1)
                Clear_File(TAB_USER_TIPO_3)
                Clear_File(TAB_AUTO_TIPO_3)
                Clear_File(TAB_USER_TIPO_6)
                Clear_File(TAB_AUTO_TIPO_6)

                if len(Comando) >= 1:
                    Usuarios = Comando
                    for linea in Usuarios:
                        s = linea.rstrip('\n')
                        if len(s) > 0:
                            # print s
                            add_Tipos_Usuarios_Nuevos(s)
                            # add_New_Tikecket(s)

                #Set_File(TAB_SERVER, Comando)
                # Clear_File(TAB_LECTOR)
                # print 'listo'
                Clear_File(CONT_RECEIVED_DATA_PATH)
                Clear_File(CONT_RECEIVED_FLAG_PATH)


# -----------------------------------------------------------
#               Pruebas de funcionamiento
# -----------------------------------------------------------
while (True):
    time.sleep(0.1)
    Resolver_Comando_Counter()

# Resolver_Comando_Counter()
