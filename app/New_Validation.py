from lib.Lib_Rout import *
from lib.Lib_File import Get_File, Clear_File, Add_Line_End, Set_File
from lib.Fun_Tipo_NFC import MD5
from lib.Lib_Threads import Create_Thread_Daemon
import time
import re


def Filtro_Tipos_Acceso(access_code, medio_acceso=1, lectora=0):
    try:
        tipo_acceso = False

        # Tipos 1, 2, 3, 4, 5 Antiguos: Qr antiguo
        if re.match("<(.*?)>", access_code):
            Filtro_Tipos_QR_Antiguo(access_code, medio_acceso, lectora)
            return True

        # Tipo 6: Dispositivos adicionales
        elif medio_acceso == 11:
            tipo_acceso = 6

        # Tipo 1, 2, 5: LLave de acceso o Reserva general con QR o Llave empleado o Pin
        elif False or medio_acceso == 2:
            tipo_acceso = 1

        if tipo_acceso:
            Validar_Acceso(
                access_code, tipo_acceso, medio_acceso, lectora)
        else:
            print "Invalid data of access"
    except Exception as e:
        pass
        # print e


def Filtro_Tipos_QR_Antiguo(access_code, medio_acceso=1, lectora=0):
    access_list = re.findall("<(.*?)>", access_code)

    for access_text in access_list:
        access_data = access_text.split(".")
        tipo_acceso = False

        # Tipo 1 0 2 o 5: LLave de acceso o Reserva general con QR o Llave empleado
        if len(access_data) == 2:
            tipo_acceso = 1

        # Tipo 3: Invitacion de unico uso
        elif len(access_data) == 5 and access_data[0] == "3":
            tipo_acceso = 3

        # Tipo 4: Invitacion de multipes uso
        elif len(access_data) == 5:
            tipo_acceso = 4
        if tipo_acceso:
            Validar_Acceso(
                access_data, tipo_acceso, medio_acceso, lectora)


def Validar_Acceso(access_data, tipo_acceso, medio_acceso, lectora):

    ans = False
    if medio_acceso == 1:
        ans = Validar_QR_Antiguo(access_data, tipo_acceso, lectora)

    elif medio_acceso == 2:
        ans = Validar_PIN(access_data, tipo_acceso, lectora)
    elif medio_acceso == 11:
        ans = Validar_NFC(access_data, tipo_acceso, lectora)

    respuesta_acceso = "Access denied"
    if ans:
        respuesta_acceso, in_out_data = ans
        if respuesta_acceso != "Access denied":
            read_time = int(time.time()*1000)
            direction = "0" if ans == "Access granted-E" else "1"

            athorization_code = in_out_data + "."+str(read_time) + \
                "."+str(medio_acceso) + "."+direction+"."+"1"
            Add_Line_End(
                TAB_ENV_SERVER,
                athorization_code+"\n"
            )
    comand_res = [
        COM_RES,
        COM_RES_S1,
        COM_RES_S2
    ]

    # Envio modulo respuesta
    Set_File(comand_res[lectora], respuesta_acceso)


def Validar_QR_Antiguo(access_data, tipo_acceso, lectora):
    access_valido = False
    access_key = False
    if tipo_acceso in [1, 4]:
        access_key = access_data[1]
        db = Get_File(TAB_USER_TIPO_1).strip().split("\n")
        for access_db in db:
            if access_data == "":
                continue

            key_db = access_db.split(".")[0]
            if access_key == key_db:
                read_time_sec = int(time.time())
                if tipo_acceso == 4:
                    if int(access_data[2]) < read_time_sec and int(access_data[3]) > read_time_sec:
                        access_valido = True
                else:
                    access_valido = True

                break
    elif tipo_acceso == 3:
        access_key = ".".join(access_data[0:3])
        db = Get_File(TAB_USER_TIPO_3).strip().split("\n")
        for access_db in db:
            if access_data == "":
                continue
            key_db = ".".join(access_db.split(".")[0:3])
            if access_key == key_db:
                access_key = False
                access_valido = True
                break

    respuesta_acceso = "Access denied"

    if access_valido:
        direction = str(lectora % 2)
        respuesta_acceso = "Access granted-E" if direction == "0" else "Access granted-S"

    in_out_data = ".".join(access_data)

    return [respuesta_acceso, in_out_data]


def Validar_PIN(access_data, tipo_acceso, lectora):
    access_valido = False
    access_key = False
    key_db = False
    if tipo_acceso == 1:
        access_key = MD5(access_data)
        db = Get_File(TAB_USER_TIPO_1).strip().split("\n")
        for access_db in db:
            if access_db == "":
                continue
            key_db, encrypted_pin = access_db.split(".")
            if access_key == encrypted_pin:
                access_valido = True
                break
    respuesta_acceso = "Access denied"
    if access_valido:
        direction = str(lectora % 2)
        respuesta_acceso = "Access granted-E" if direction == "0" else "Access granted-S"

    in_out_data = "."+str(key_db)

    return [respuesta_acceso, in_out_data]


def Validar_NFC(access_data, tipo_acceso, lectora):
    access_valido = False
    access_key = False
    key_db = False
    if tipo_acceso == 6:
        access_key = MD5(access_data)
        db = Get_File(TAB_USER_TIPO_6).strip().split("\n")
        for access_db in db:
            if access_db == "":
                continue
            key_db, encrypted_pin = access_db.split(".")
            if access_key == encrypted_pin:
                access_valido = True
                break
    respuesta_acceso = "Access denied"
    if access_valido:
        direction = str(lectora % 2)
        respuesta_acceso = "Access granted-E" if direction == "0" else "Access granted-S"

    in_out_data = "6."+str(key_db)+"."+str(access_data)+".11"

    return [respuesta_acceso, in_out_data]


def Recibir_Codigo_Accesso():
    # Medio de acceso 1:QR
    if Get_File(STATUS_QR) == '1':
        Create_Thread_Daemon(Filtro_Tipos_Acceso,
                             Get_File(COM_QR), 1, 0)
        Clear_File(STATUS_QR)

    if Get_File(STATUS_QR_S1) == '1':
        Create_Thread_Daemon(Filtro_Tipos_Acceso,
                             Get_File(COM_QR_S1), 1, 1)
        Clear_File(STATUS_QR_S1)

    if Get_File(STATUS_QR_S2) == '1':
        Create_Thread_Daemon(Filtro_Tipos_Acceso,
                             Get_File(COM_QR_S2), 1, 2)
        Clear_File(STATUS_QR_S2)

    # Medio de acceso 2:PIN
    if Get_File(STATUS_TECLADO) == '1':
        Create_Thread_Daemon(Filtro_Tipos_Acceso,
                             Get_File(COM_TECLADO), 2, 0)
        Clear_File(STATUS_TECLADO)

    if Get_File(STATUS_TECLADO_S1) == '1':
        Create_Thread_Daemon(Filtro_Tipos_Acceso,
                             Get_File(COM_TECLADO_S1), 2, 1)
        Clear_File(STATUS_TECLADO_S1)

    if Get_File(STATUS_TECLADO_S2) == '1':
        Create_Thread_Daemon(Filtro_Tipos_Acceso,
                             Get_File(COM_TECLADO_S2), 2, 2)
        Clear_File(STATUS_TECLADO_S2)

    # Medio de acceso 5-11:PIN
    if Get_File(STATUS_NFC) == '1':
        Create_Thread_Daemon(Filtro_Tipos_Acceso,
                             Get_File(COM_NFC), 11, 0)
        Clear_File(STATUS_NFC)

    if Get_File(STATUS_NFC_S1) == '1':
        Create_Thread_Daemon(Filtro_Tipos_Acceso,
                             Get_File(COM_NFC_S1), 11, 1)
        Clear_File(STATUS_NFC_S1)

    if Get_File(STATUS_NFC_S2) == '1':
        Create_Thread_Daemon(Filtro_Tipos_Acceso,
                             Get_File(COM_NFC_S2), 11, 2)
        Clear_File(STATUS_NFC_S2)


while True:
    sleep_time = 0.5
    time.sleep(sleep_time)
    Recibir_Codigo_Accesso()
