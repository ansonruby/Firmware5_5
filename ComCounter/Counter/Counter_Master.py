#!/home/pi/Firmware/ComCounter/Counter/bin/python3
from threading import Thread
from flask import Flask, request
from flask_cors import CORS
from Crypto.Cipher import AES
from waitress import serve
import websocket
import requests
import json
import time
import os
import base64
import hashlib
import uuid
import logging
import datetime
import subprocess
import ast


CURRENT_DIR_PATH = os.path.dirname(os.path.realpath(__file__))

# Cloud server constants
CLOUD_SERVER_DOMAIN_PATH = CURRENT_DIR_PATH + \
    "/../../db/Config/Server/Dominio_Servidor.txt"
CLOUD_SERVER_IP_PATH = CURRENT_DIR_PATH + \
    "/../../db/Config/Server/IP_Servidor.txt"
CLOUD_SERVER_BEST_OPTION_PATH = CURRENT_DIR_PATH + \
    "/../../db/Config/Server/Mejor_Conexion.txt"
DEVICE_CURRENT_UUID = uuid.uuid1()

# Internal db constants
DB_DIR_NAME = CURRENT_DIR_PATH+"/db"
QR_LIST_PATH = DB_DIR_NAME+"/data.txt"
QR_LIST_UPDATED_PATH = DB_DIR_NAME+"/data_updated.txt"
AUTH_LIST_PATH = DB_DIR_NAME+"/auth.txt"
OFFLINE_LIST_PATH = DB_DIR_NAME+"/offline.txt"
LAST_LOGIN_LIST_PATH = DB_DIR_NAME+"/lastLog.txt"
ACTIVE_MASTER_PATH = DB_DIR_NAME+"/activeConection.txt"
COUNTER_LOGS_PATH = DB_DIR_NAME+"/masterLogs.txt"
CONFIG_PATH = DB_DIR_NAME+"/config.json"
ACTIVE_CONECTION = CURRENT_DIR_PATH+"/../db/flagtosend.txt"


# Cloud server variables
server_update_time = 60 * 10
cloud_server_domain = ""
login_token = ""
bookingOffice_id = ""
active_devices = []
active_server_updater = False
update_scanners = False
save_logs = False
max_petition_timeout = 60
scanners_port = 1238
local_server_port = 8090
counter_user = ""
counter_password = ""
start_up_time = 0


def Get_Rout_server():
    mejor_opcion = ""
    IP_Ser = ""
    Domi_Ser = ""
    with open(CLOUD_SERVER_DOMAIN_PATH, 'r', encoding='utf-8', errors='replace') as df:
        Domi_Ser = df.read().strip()
        df.close()
    with open(CLOUD_SERVER_IP_PATH, 'r', encoding='utf-8', errors='replace') as df:
        IP_Ser = df.read().strip()
        df.close()
    with open(CLOUD_SERVER_BEST_OPTION_PATH, 'r', encoding='utf-8', errors='replace') as df:
        mejor_opcion = df.read().strip()
        df.close()

    opciones = {'0': 'http://' + IP_Ser,
                '1': 'http://' + Domi_Ser,
                '10': 'http://' + IP_Ser,
                '11': 'http://' + IP_Ser,
                '100': 'https://' + IP_Ser,
                '101': 'https://' + IP_Ser,
                '110': 'https://' + IP_Ser,
                '111': 'https://' + IP_Ser,
                '1000': 'https://' + Domi_Ser,
                '1001': 'https://' + Domi_Ser,
                '1010': 'http://' + IP_Ser,
                '1011': 'http://' + IP_Ser,
                '1100': 'https://' + IP_Ser,
                '1101': 'https://' + IP_Ser,
                '1110': 'https://' + IP_Ser,
                '1111': 'https://' + IP_Ser}

    # return 'https://solutions.fusepong.com'
    # return 'http://192.168.0.44:3000'
    return opciones[mejor_opcion]


def log_in():
    try:
        data = encrypt({"attributes": {'email': counter_user,
                                       'password': counter_password}}).decode("utf-8")
        petition = requests.post(
            url=cloud_server_domain+"/api/users/sign_in",
            data={"data": data},
            headers={'X-Device-ID': str(DEVICE_CURRENT_UUID)},
            timeout=max_petition_timeout)
        if petition.status_code == 201:
            last_log_data = []
            with open(LAST_LOGIN_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
                last_log_text = df.read().strip()
                df.close()
                last_log_data = last_log_text.split("\n")
            if len(last_log_data) > 0 and last_log_data[0].strip() != data.strip():
                with open(OFFLINE_LIST_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
                    dfw.write("")
                    dfw.close()
            with open(LAST_LOGIN_LIST_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
                last_log_data[0] = data
                dfw.write("\n".join(last_log_data))
                dfw.close()
            return [petition.json()['data']['id'], petition.json()['meta']['authentication_token']]
    except Exception as e:
        print_logs("[Master]:Log_in error "+repr(e))
        return None


def get_devices():
    petition = requests.get(
        url=cloud_server_domain+"/api/app/scan_devices/find_ip_devices",
        params={"id": bookingOffice_id},
        headers={'X-Device-ID': str(DEVICE_CURRENT_UUID),
                 "Authorization": "Bearer "+login_token},
        timeout=max_petition_timeout)

    if petition.status_code == 200:
        last_log_data = []
        data = petition.json()["data"]["scanners"]
        with open(LAST_LOGIN_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
            last_log_text = df.read().strip()
            df.close()
            last_log_data = last_log_text.split("\n")
        with open(LAST_LOGIN_LIST_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
            if len(last_log_data) < 3:
                last_log_data.append(";".join(
                    list(map(lambda scanner_ip: str(scanner_ip[0])+","+str(scanner_ip[1]), data))))
            else:
                last_log_data = last_log_data[:3]
                last_log_data[2] = ";".join(
                    list(map(lambda scanner_ip: str(scanner_ip[0])+","+str(scanner_ip[1]), data)))
            dfw.write("\n".join(last_log_data))
            dfw.close()
        return data
    else:
        return []


def get_devices_offline():
    last_log_data = []
    with open(LAST_LOGIN_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
        last_log_text = df.read().strip()
        df.close()
        last_log_data = last_log_text.split("\n")
    return [scanner_ip.split(",") for scanner_ip in last_log_data[2].split(";") if scanner_ip.split(",")[0] == "None"]


def get_users():
    tickets_offline = None
    with open(OFFLINE_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
        tickets_offline_text = df.read().strip()
        df.close()
        if tickets_offline_text != "":
            tickets_offline = tickets_offline_text.split("\n")
    if tickets_offline:
        tickets_offline_json = []
        for ticket in tickets_offline:
            ticket_json = {}
            if ticket.strip() == "":
                continue

            ticket_json = json.loads(ticket)
            if not "user_id" in ticket_json:
                ticket_json["user_id"] = bookingOffice_id
            tickets_offline_json.append(ticket_json)
        petition = requests.post(
            url=cloud_server_domain+"/api/app/bookings/create_ticket",
            data={"data": encrypt(
                {"tickets": tickets_offline_json})},
            headers={'X-Device-ID': str(DEVICE_CURRENT_UUID),
                     "Authorization": "Bearer "+login_token},
            timeout=max_petition_timeout)

    in_out = None
    with open(AUTH_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
        auth_list_text = df.read().strip()
        df.close()
        if auth_list_text != "":
            in_out = auth_list_text.split("\n")
    if in_out:
        petition = requests.post(
            url=cloud_server_domain+"/api/access/update_scan_actions",
            data={"data": encrypt(
                {"bookingOffice_id": bookingOffice_id, "in_out": in_out})},
            headers={'X-Device-ID': str(DEVICE_CURRENT_UUID),
                     "Authorization": "Bearer "+login_token},
            timeout=max_petition_timeout)
        if petition.status_code == 200 or petition.status_code == 202:
            with open(AUTH_LIST_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
                dfw.write("")
                dfw.close()
    petition = requests.get(
        url=cloud_server_domain+"/api/access/get_granted_users_pi",
        params={"bookingOffice_id": bookingOffice_id},
        headers={'X-Device-ID': str(DEVICE_CURRENT_UUID),
                 "Authorization": "Bearer "+login_token},
        timeout=max_petition_timeout)
    if petition.status_code == 200:
        return save_users(petition.json())


def save_users(data):
    granted_users = []
    granted_users.extend(data["data"])
    granted_users.extend(data["invitations"])
    with open(QR_LIST_UPDATED_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
        dfw.write("\n".join(granted_users)+"\n")
        dfw.close()

    offline_list = []
    with open(OFFLINE_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
        offline_list_text = df.read().strip()
        df.close()
        if offline_list_text != "":
            offline_list = offline_list_text.split("\n")
            with open(OFFLINE_LIST_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
                dfw.write("")
                dfw.close()

    for ticket in offline_list:
        if ticket.strip() != "":
            create_ticket(json.loads(ticket), False, True)

    for ticket in data["tickets"]:
        create_ticket(ticket, True, True)

    qr_list = ""
    qr_list_updated = ""
    with open(QR_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
        qr_list = df.read().strip()
        df.close()
    with open(QR_LIST_UPDATED_PATH, 'r', encoding='utf-8', errors='replace') as df:
        qr_list_updated = df.read().strip()
        df.close()
    # Compare if the db and updated db has diferent
    if int(hashlib.sha256(qr_list.encode('utf-8')).hexdigest(), 16) % 10**8 != int(hashlib.sha256(qr_list_updated.encode('utf-8')).hexdigest(), 16) % 10**8:
        os.rename(QR_LIST_PATH, QR_LIST_PATH+".bk")
        os.rename(QR_LIST_UPDATED_PATH, QR_LIST_PATH)
        os.remove(QR_LIST_PATH+".bk")
        open(QR_LIST_UPDATED_PATH, 'w', encoding='utf-8',
             errors='replace').close()
        return True
    else:
        with open(QR_LIST_UPDATED_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
            dfw.write("")
            dfw.close()
    return False


def auth_petition(qr, ws, direction="0"):
    try:
        qr_list = []
        data = qr.split(".")
        ans = False
        access_identifier = "1"
        with open(QR_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
            qr_list_text = df.read().strip()
            df.close()
            qr_list = qr_list_text.split("\n")
        for compare_qr in qr_list:
            if compare_qr == "":
                continue
            compare_data = compare_qr.split(".")
            if compare_data[0] == "6" and data[0] == "6" and compare_data[2] == data[1]:
                ans = True
                if len(compare_data) > 3:
                    access_identifier = compare_data[3]
                    qr = compare_qr
                else:
                    access_identifier = "11"
                    qr = compare_qr+".11"
                break
            elif len(data) == 2 and len(compare_data) == 2 and data[1] == compare_data[0]:
                access_identifier = "1"
                ans = True
                break
            elif len(data) == 2 and len(compare_data) == 2 and data[0] == "" and data[1] == compare_data[1]:
                qr = "."+compare_data[0]
                access_identifier = "2"
                ans = True
                break
            elif len(data) == 5 and len(compare_data) == 5 and compare_data[0] == "3" and data[0] == "3" and ".".join(data[0:-1]) == ".".join(compare_data[0:-1]):
                access_identifier = "1"
                offline_list = []
                with open(OFFLINE_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
                    offline_list_text = df.read().strip()
                    df.close()
                    if offline_list_text.strip() != "":
                        offline_list = offline_list_text.split("\n")
                for existent_ticket_text in offline_list:
                    if existent_ticket_text.strip() == "":
                        continue
                    existent_ticket = json.loads(existent_ticket_text)
                    if existent_ticket["qr"] == compare_qr:
                        if int(existent_ticket["uses"]) > 1:
                            existent_ticket["uses"] = str(
                                int(existent_ticket["uses"])-1)
                            offline_position = offline_list.index(
                                existent_ticket_text)
                            existent_ticket_text = json.dumps(existent_ticket)
                            offline_list[offline_position] = existent_ticket_text
                        else:
                            offline_list.remove(existent_ticket_text)
                        break
                with open(OFFLINE_LIST_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
                    dfw.write("\n".join(offline_list))
                    dfw.close()
                qr_list.remove(compare_qr)
                ans = True
                with open(QR_LIST_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
                    dfw.write("\n".join(qr_list))
                    dfw.close()
                break
            elif len(data) == 5 and len(compare_data) == 5 and compare_data[0] == "4" and ".".join(data[1:]) == ".".join(compare_data[1:]):
                ans = True
                break
        if ans == True:
            with open(AUTH_LIST_PATH, 'a', encoding='utf-8', errors='replace') as dfw:
                dfw.write(qr+"."+str(int(time.time()*1000.0)) +
                          "."+access_identifier+"."+direction+".1."+str(ws.server_id)+"\n")
                dfw.close()
        return ans
    except Exception as e:
        print_logs("[Socket from "+str(ws.url) +
                   "]:Error authorizing qr "+qr+" = "+repr(e))
        return False


def save_authorization(qr, ws):
    try:
        qr_list = []
        data = qr.split(".")
        time = data[-4]
        data = data[0:-4]
        ans = False
        access_identifier = "1"
        with open(QR_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
            qr_list_text = df.read().strip()
            df.close()
            qr_list = qr_list_text.split("\n")
        for compare_qr in qr_list:
            if compare_qr == "":
                continue
            compare_data = compare_qr.split(".")
            if compare_data[0] == "6" and data[0] == "6" and compare_data[2] == data[2]:
                ans = True
                if len(compare_data) > 3:
                    access_identifier = compare_data[3]
                    qr = compare_qr
                else:
                    access_identifier = "11"
                    qr = compare_qr+".11"
                break
            elif len(data) == 2 and len(compare_data) == 2 and data[1] == compare_data[0]:
                access_identifier = "1"
                ans = True
                break
            elif len(data) == 2 and len(compare_data) == 2 and data[0] == "" and data[1] == compare_data[1]:
                data[1] = "."+compare_data[0]
                access_identifier = "2"
                ans = True
                break
            elif compare_data[0] == "3" and data[0] == "3" and ".".join(data[0:-1]) == ".".join(compare_data[0:-1]):
                access_identifier = "1"
                offline_list = []
                with open(OFFLINE_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
                    offline_list_text = df.read().strip()
                    df.close()
                    if offline_list_text.strip() != "":
                        offline_list = offline_list_text.split("\n")
                for existent_ticket_text in offline_list:
                    if existent_ticket_text.strip() == "":
                        continue
                    existent_ticket = json.loads(existent_ticket_text)
                    if existent_ticket["qr"] == compare_qr:
                        if int(existent_ticket["uses"]) > 1:
                            existent_ticket["uses"] = str(
                                int(existent_ticket["uses"])-1)
                            offline_position = offline_list.index(
                                existent_ticket_text)
                            existent_ticket_text = json.dumps(existent_ticket)
                            offline_list[offline_position] = existent_ticket_text
                        else:
                            offline_list.remove(existent_ticket_text)
                        break
                with open(OFFLINE_LIST_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
                    dfw.write("\n".join(offline_list))
                    dfw.close()
                qr_list.remove(compare_qr)
                ans = True
                with open(QR_LIST_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
                    dfw.write("\n".join(qr_list))
                    dfw.close()
                break
            elif compare_data[0] == "4" and ".".join(data[1:]) == ".".join(compare_data[1:]):
                ans = True
                break
        if ans == True:
            with open(AUTH_LIST_PATH, 'a', encoding='utf-8', errors='replace') as dfw:
                dfw.write(".".join(data)+"."+time +
                          "."+access_identifier+".0.1."+str(ws.server_id)+"\n")
                dfw.close()
        return ans
    except Exception as e:
        print_logs("[Socket from "+str(ws.url) +
                   "]:Error saving device authorization of qr "+qr+" = "+repr(e))
        return False


def create_ticket(ticket, new_ticket=True, update_db=False):
    valid_ref_number = True
    offline_list = []
    with open(OFFLINE_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
        offline_list_text = df.read().strip()
        df.close()
        if offline_list_text.strip() != "":
            offline_list = offline_list_text.split("\n")
    for existent_ticket in offline_list:
        if existent_ticket.strip() == "":
            continue
        existent_ticket = json.loads(existent_ticket)
        if existent_ticket["ref_number"] == ticket["ref_number"]:
            valid_ref_number = False
            break
    if valid_ref_number:
        ticket_time = ticket["end_time"]
        ticket_time_list = ticket_time.split(" GMT ")
        ticket_datetime = datetime.datetime.strptime(
            ticket_time_list[0], '%Y-%m-%d %H:%M')-datetime.timedelta(hours=int("".join(list(ticket_time_list[1])[:3])))
        if ticket_datetime >= datetime.datetime.now().utcnow():
            qr_type = 3
            encrypted_rut = encrypt(
                ticket["identification_number"]).decode("utf-8")
            if not "uses" in ticket:
                ticket["uses"] = ticket["quantity"]
            ticket["qr"] = str(qr_type) + "." + encrypt(bookingOffice_id).decode("utf-8") + \
                "." + encrypted_rut + "." + "1" + ".0"
            if not "user_id" in ticket:
                ticket["user_id"] = bookingOffice_id
            qrs = (ticket["qr"]+"\n")*int(ticket["uses"])
            db = QR_LIST_PATH
            if update_db:
                db = QR_LIST_UPDATED_PATH
            with open(db, 'a', encoding='utf-8', errors='replace') as dfw:
                dfw.write(qrs)
                dfw.close()
            with open(OFFLINE_LIST_PATH, 'a', encoding='utf-8', errors='replace') as dfw:
                dfw.write(json.dumps(ticket)+"\n")
                dfw.close()
            if new_ticket:
                print_logs(
                    "[Master]:Created ticket with ref_number="+ticket["ref_number"])
    return valid_ref_number


def search_user_tickets(identification_number):
    offline_list = []
    ticket_list = []
    with open(OFFLINE_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
        offline_list_text = df.read().strip()
        df.close()
        if offline_list_text.strip() != "":
            offline_list = offline_list_text.split("\n")
    for existent_ticket_text in offline_list:
        if existent_ticket_text.strip() == "":
            continue
        existent_ticket = json.loads(existent_ticket_text)
        if int(existent_ticket["identification_number"]) == int(identification_number):
            old_ticket_list = ""
            if len(ticket_list) < 1:
                ticket_list.append("")
            else:
                old_ticket_list = ";"+ticket_list[0]
            ticket_list[0] = ";".join(
                ["<" + ".".join(existent_ticket["qr"].split(".")[0:-1]) +
                    "." + str(int(time.time()*1000.0)) +
                    ">"] * int(existent_ticket["uses"])) + old_ticket_list
            if len(ticket_list) > 1:
                ticket_list[1].append(existent_ticket)
            else:
                ticket_list.append([existent_ticket])
    return ticket_list


def encrypt(data):
    iv = base64.b64decode("G7qeaR2Yb4DAgk92ZQHdjQ==")
    passphraseDgst = hashlib.sha256('ImAwesomeAndHappy'.encode()).digest()
    cipher = AES.new(passphraseDgst, AES.MODE_CBC, iv)
    data = json.dumps(data)
    pad = 16 - len(data) % 16
    data += pad * chr(pad)
    encyrpted_data = base64.b64encode(cipher.encrypt(data)).strip()
    return encyrpted_data


def server_updater():
    global cloud_server_domain, login_token, bookingOffice_id,  update_scanners,  server_update_time
    while True:
        await_time = server_update_time
        try:
            cloud_server_domain = Get_Rout_server()
            credentials = log_in()
            if credentials:
                [bookingOffice_id, login_token] = credentials
                update_scanners = get_users()
            else:
                print_logs("[Master]:Desconection of internet")
                await_time = 60

        except Exception as e:
            print_logs("[Master]:Internet error "+repr(e))
            await_time = 60

        time.sleep(await_time)


def socket_guardian():
    global active_devices, update_scanners
    while True:
        new_active_devices = []
        for device in active_devices:
            try:
                qr_list_size = 0
                if update_scanners:
                    with open(QR_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
                        qr_list = df.read().strip()
                        df.close()
                        qr_list_size = len(qr_list.split("\n"))
                if not "ws" in device or device["ws"].sock == None:
                    def ws_run():
                        ws = websocket.WebSocketApp(device["ip"],
                                                    on_open=socket_on_open,
                                                    on_message=socket_on_message,
                                                    on_error=socket_on_error,
                                                    on_close=socket_on_close)
                        ws.procesing = True
                        ws.server_id = device["id"]
                        device["ws"] = ws
                        ws.run_forever()
                    Thread(target=ws_run).start()
                elif not device["ws"].procesing:
                    if update_scanners:
                        device["ws"].send(json.dumps({'type': 'updateDevice',
                                                      'size': [qr_list_size, 0], 'status': "1"})+"////\n" + datetime.datetime.now().strftime("%mFu%dse%Ypong"))
                    else:
                        device["ws"].send(json.dumps(
                            {'type': "Test connection", 'status': "1"}))
            except Exception as e:
                print_logs("[Master]: Error in conection of device " +
                           device["ip"]+" = "+repr(e))
            finally:
                new_active_devices.append(device)

        if update_scanners:
            update_scanners = False
        active_devices = new_active_devices

        time.sleep(0.8)


def socket_on_open(ws):
    ws.procesing = True
    if not os.path.exists(DB_DIR_NAME):
        os.makedirs(DB_DIR_NAME)
    if not os.path.exists(QR_LIST_PATH):
        open(QR_LIST_PATH, 'w', encoding='utf-8', errors='replace').close()


def socket_on_message(ws, msg):
    try:
        msg = msg.strip()
        print_logs("[Socket from "+str(ws.url)+" to Master]:"+str(msg))
        ans = False
        ws.procesing = True
        req = msg.split("////\n")
        header = json.loads(req[0])
        if header["type"] == "update":
            qr_list_size = 0
            with open(QR_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
                qr_list = df.read().strip()
                df.close()
                qr_list_size = len(qr_list.split("\n"))
            ans = json.dumps({'type': 'updateDevice',
                              'size': [qr_list_size, 0], 'status': "1"})+"////\n" + datetime.datetime.now().strftime("%mFu%dse%Ypong")
        else:
            if header["type"] == "authTicket":
                access = ""
                direction = "0" if not "direction" in header else header["direction"]
                if auth_petition(req[1], ws, direction) == True:
                    access = "Access granted-E.0" if direction == "0" else "Access granted-S.0"
                else:
                    access = "Access denied.-1"
                ans = json.dumps(
                    {'type': "authTicket", 'status': "1", 'size': 1})+"////\n"+access

                ws.send(ans)
                if ans:
                    print_logs("[Master to "+str(ws.url)+"]:"+str(ans))
            elif header["type"] == "delTickets":
                for access in req[1].split("\n"):
                    save_authorization(access, ws)
            ans = json.dumps({'type': "recived", 'status': "1"})

        if ans:
            ws.send(ans)
            print_logs("[Master to "+str(ws.url)+"]:"+str(ans))

        ws.procesing = False
    except Exception as e:
        print_logs("[Socket from "+str(ws.url) +
                   "]:Error procesing message "+repr(e))
        ws.close()


def socket_on_error(ws, error):
    ws.sock = None
    ws.close()
    print_logs("[Socket from "+str(ws.url)+"]:Error "+repr(error))


def socket_on_close(ws, close_status_code, close_msg):
    ws.sock = None
    ws.close()
    print_logs("[Socket from "+str(ws.url)+"]:Closed conection sucessfully ")


def server_http():
    global local_server_port
    app = Flask(__name__)

    @app.route('/scannersPetition', methods=['GET'])
    def scannersPetition():
        if request.args.get('scannerAccessKey') == datetime.datetime.now().strftime("%mFu%dse%Ypong"):
            qr_list = ""
            with open(QR_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
                qr_list = df.read().strip()
                df.close()
            return {"status": 201, "tickets": qr_list}, 201
        else:
            return {"status": 401, "error": "Invalid terminal"}, 401

    @app.route('/api_authentication', methods=['POST'])
    def api_authentication():
        last_log_data = []
        with open(LAST_LOGIN_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
            last_log_text = df.read().strip()
            df.close()
            last_log_data = last_log_text.split("\n")
        json_response = ast.literal_eval(base64.b64decode(
            request.json['credentials']).decode('utf-8'))
        credentials = encrypt({"attributes": {
            "email": json_response["email"], "password": json_response["password"]}}).decode("utf-8")
        if last_log_data[0] == credentials:
            return {"status": 201, "authorization_token": last_log_data[0]}, 201
        else:
            return {"status": 422, "error_message": "Credenciales incorrectas"}, 422

    @app.route('/process_voucher', methods=['POST'])
    def process_voucher():
        last_log_data = []
        with open(LAST_LOGIN_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
            last_log_text = df.read().strip()
            df.close()
            last_log_data = last_log_text.split("\n")
        auth = request.headers.get("Authorization") or request.headers.get(
            "authorization") or request.headers.get("AUTHORIZATION")
        if auth.strip() == "Bearer "+last_log_data[0]:
            valid_ref = create_ticket(ast.literal_eval(base64.b64decode(
                request.json['ticket']).decode('utf-8')))
            if valid_ref:
                return {"status": 201, "message": "Informacion recibida y procesada correctamente"}, 201
            else:
                return {"status": 400, "error_message": "ref_number repetido"}, 400
        else:
            return {"status": 401, "error_message": "Token de acceso invalido"}, 401

    @app.route('/search_active_tickets', methods=['POST'])
    def search_active_tickets():
        last_log_data = []
        with open(LAST_LOGIN_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
            last_log_text = df.read().strip()
            df.close()
            last_log_data = last_log_text.split("\n")
        auth = request.headers.get("Authorization") or request.headers.get(
            "authorization") or request.headers.get("AUTHORIZATION")
        if auth.strip() == "Bearer "+last_log_data[0]:
            ticket_list = search_user_tickets(base64.b64decode(
                request.json['identification_number']).decode('utf-8'))
            if ticket_list:
                return {"status": 200, "tickets": ticket_list}, 200
            else:
                return {"status": 422, "error_message": "EL usuario no posee acceso"}, 422
        else:
            return {"status": 401, "error_message": "Token de acceso invalido"}, 401

    log = logging.getLogger("werkzeug")
    log.disabled = True
    app.logger.disabled = True
    CORS(app)
    print_logs("[Master]:Serving data in 0.0.0.0:"+str(local_server_port))
    serve(app, host="0.0.0.0", port=local_server_port)


def print_logs(text):
    if save_logs:
        with open(COUNTER_LOGS_PATH, 'a', encoding='utf-8', errors='replace') as dfw:
            dfw.write("\n"+str(text).replace("\n", " 'new line' "))
            dfw.close()


def config_counter():
    global DB_DIR_NAME, QR_LIST_PATH, LAST_LOGIN_LIST_PATH, AUTH_LIST_PATH, ACTIVE_MASTER_PATH, OFFLINE_LIST_PATH, CONFIG_PATH, COUNTER_LOGS_PATH
    global scanners_port, local_server_port, server_update_time, save_logs, counter_user, counter_password, start_up_time
    if not os.path.exists(DB_DIR_NAME):
        os.makedirs(DB_DIR_NAME)
    if not os.path.exists(QR_LIST_PATH):
        open(QR_LIST_PATH, 'w', encoding='utf-8',
             errors='replace').close()
    if not os.path.exists(QR_LIST_UPDATED_PATH):
        open(QR_LIST_UPDATED_PATH, 'w', encoding='utf-8',
             errors='replace').close()
    if not os.path.exists(AUTH_LIST_PATH):
        open(AUTH_LIST_PATH, 'w', encoding='utf-8',
             errors='replace').close()
    if not os.path.exists(LAST_LOGIN_LIST_PATH):
        open(LAST_LOGIN_LIST_PATH, 'w', encoding='utf-8',
             errors='replace').close()
    if not os.path.exists(ACTIVE_MASTER_PATH):
        open(ACTIVE_MASTER_PATH, 'w', encoding='utf-8',
             errors='replace').close()
    if not os.path.exists(OFFLINE_LIST_PATH):
        open(OFFLINE_LIST_PATH, 'w', encoding='utf-8',
             errors='replace').close()
    if not os.path.exists(COUNTER_LOGS_PATH):
        open(COUNTER_LOGS_PATH, 'w', encoding='utf-8',
             errors='replace').close()
    if not os.path.exists(CONFIG_PATH):
        open(CONFIG_PATH, 'w', encoding='utf-8',
             errors='replace').close()
    configs = ""
    with open(CONFIG_PATH, 'r', encoding='utf-8', errors='replace') as df:
        configs = df.read().strip()
        df.close()
    if configs == "":
        configs = json.dumps({})

    try:
        configs_json = ast.literal_eval(configs)
    except Exception as e:
        print_logs("[Master]:Error reading config file " +
                   str(CONFIG_PATH)+" = "+repr(e))
        print_logs("[Master]:Reset config file to default settings")
        configs_json = {}

    if "counter_user" in configs_json:
        counter_user = configs_json["counter_user"]
    else:
        configs_json["counter_user"] = counter_user

    if "counter_password" in configs_json:
        counter_password = configs_json["counter_password"]
    else:
        configs_json["counter_password"] = counter_password

    if "scanners_port" in configs_json:
        scanners_port = configs_json["scanners_port"]
    else:
        configs_json["scanners_port"] = scanners_port

    if "local_server_port" in configs_json:
        local_server_port = configs_json["local_server_port"]
    else:
        configs_json["local_server_port"] = local_server_port

    if "server_update_time" in configs_json:
        server_update_time = int(configs_json["server_update_time"])
    else:
        configs_json["server_update_time"] = server_update_time

    if "start_up_time" in configs_json:
        start_up_time = int(configs_json["start_up_time"])
    else:
        configs_json["start_up_time"] = start_up_time

    if "save_logs" in configs_json:
        save_logs = str(configs_json["save_logs"]).lower() == "True".lower()
    else:
        configs_json["save_logs"] = str(
            str(save_logs).lower() == "True".lower())

    configs = json.dumps(configs_json, indent=2)

    with open(CONFIG_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
        dfw.write(configs)
        dfw.close()


if __name__ == "__main__":
    config_counter()
    if save_logs:
        with open(COUNTER_LOGS_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
            dfw.write("Counter master logs\n" +
                      "Fecha: "+str(datetime.date.today()))
            dfw.close()
    with open(ACTIVE_MASTER_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
        dfw.write("")
        dfw.close()
    Thread(target=server_http).start()
    time.sleep(0.8)
    while True:
        try:
            exisṭ_other_connection = False
            if os.path.exists(ACTIVE_CONECTION):
                with open(ACTIVE_CONECTION, 'r', encoding='utf-8', errors='replace') as df:
                    exisṭ_other_connection = df.read().strip() != "3"
                    df.close()
            if not exisṭ_other_connection:
                ips = subprocess.getstatusoutput('hostname -I')
                if ips[0] == 0 or start_up_time != 0:
                    await_time = 0
                    if start_up_time == 0:
                        try:
                            ips_list = ips[1].strip().split(" ")
                            ip_min_number = float(ips_list[0].split(".")[-1])
                            for ip in ips_list:
                                ip_numbers = ip.split(".")
                                if len(ip_numbers) == 4 and float(ip_numbers[-1]) < ip_min_number:
                                    ip_min_number = float(ip_numbers[-1])
                            await_time = int(ip_min_number/2)
                        except:
                            await_time = 0
                            print_logs("error find ip, defaut await time 0")
                    else:
                        await_time = start_up_time
                    time.sleep(await_time)
                    if os.path.exists(ACTIVE_CONECTION):
                        with open(ACTIVE_CONECTION, 'r', encoding='utf-8', errors='replace') as df:
                            exisṭ_other_connection = df.read().strip() != "3"
                            df.close()
                    if exisṭ_other_connection:
                        continue
                    if not os.path.exists(DB_DIR_NAME):
                        os.makedirs(DB_DIR_NAME)
                    if not os.path.exists(QR_LIST_PATH):
                        open(QR_LIST_PATH, 'w', encoding='utf-8',
                             errors='replace').close()
                    if not os.path.exists(OFFLINE_LIST_PATH):
                        open(OFFLINE_LIST_PATH, 'w', encoding='utf-8',
                             errors='replace').close()

                    cloud_server_domain = Get_Rout_server()
                    credentials = log_in()
                    if credentials:
                        [bookingOffice_id, login_token] = credentials
                        last_log_data = []
                        with open(LAST_LOGIN_LIST_PATH, 'r', encoding='utf-8', errors='replace') as df:
                            last_log_text = df.read().strip()
                            df.close()
                            last_log_data = last_log_text.split("\n")
                        with open(LAST_LOGIN_LIST_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
                            if len(last_log_data) < 2:
                                last_log_data.append("")
                            last_log_data[0] = last_log_data[0]
                            last_log_data[1] = bookingOffice_id
                            dfw.write("\n".join(last_log_data))
                            dfw.close()
                        active_devices = []
                        for device_ip in get_devices():
                            if device_ip[0] and device_ip[0].strip() != "":
                                device = {"ip": "ws://"+device_ip[0] +
                                          ":"+str(scanners_port)+"/", "id": device_ip[1], "active": True}
                                active_devices.append(device)
                    else:
                        active_devices = []
                        for device_ip in get_devices_offline():
                            if device_ip[0] and device_ip[0].strip() != "":
                                device = {"ip": "ws://"+device_ip[0] +
                                          ":"+str(scanners_port)+"/", "id": device_ip[1], "active": True}
                                active_devices.append(device)

                    server_update = Thread(target=server_updater)
                    server_update.start()

                    with open(ACTIVE_MASTER_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
                        dfw.write("1")
                        dfw.close()

                    socket_guardian()

        except Exception as e:
            print_logs("[Master]:Load Error "+repr(e))
            with open(ACTIVE_MASTER_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
                dfw.write("")
                dfw.close()
        time.sleep(1)
