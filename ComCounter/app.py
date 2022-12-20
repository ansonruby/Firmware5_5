from server import Websocket, WebsocketServer
import os
import json
import requests
import time
import ast
import datetime

SLAVE_PORT = 1238
SERVER_PORT = 8090
AWAIT_TIME = 0.2
AWAIT_PACKAGE_TIME = 0.02
MAX_PACKAGE_BYTES_SIZE = 6000
AWAIT_TIME_FROM_LAST_MESSAGE = 2
SHOW_PRINT_MSG = False

DB_DIR_NAME = os.path.dirname(os.path.realpath(__file__))+"/db"

CONFIG_PATH = DB_DIR_NAME+"/../Counter/db/config.json"

SEND_FLAG_PATH = DB_DIR_NAME+"/flagtosend.txt"
SEND_DATA_PATH = DB_DIR_NAME+"/datatosend.txt"

RECIVED_FLAG_PATH = DB_DIR_NAME+"/flagreceived.txt"
RECIVED_DATA_PATH = DB_DIR_NAME+"/datareceived.txt"

SLAVE_LOGS_PATH = DB_DIR_NAME+"/slaveLogs.txt"

if os.path.exists(CONFIG_PATH):
    configs = ""
    with open(CONFIG_PATH, 'r', encoding='utf-8', errors='replace') as df:
        configs = df.read().strip()
        df.close()
    if configs == "":
        configs = json.dumps({})

    configs_json = {}
    try:
        configs_json = ast.literal_eval(configs)
    except:
        configs_json = {}

    if "scanners_port" in configs_json:
        SLAVE_PORT = configs_json["scanners_port"]
    else:
        configs_json["scanners_port"] = SLAVE_PORT

    if "local_server_port" in configs_json:
        SERVER_PORT = configs_json["local_server_port"]
    else:
        configs_json["local_server_port"] = SERVER_PORT

    if "save_logs" in configs_json:
        SHOW_PRINT_MSG = str(
            configs_json["save_logs"]).lower() == "True".lower()
    else:
        configs_json["save_logs"] = str(
            str(SHOW_PRINT_MSG).lower() == "True".lower())

    configs = json.dumps(configs_json, indent=2)

    with open(CONFIG_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
        dfw.write(configs)
        dfw.close()
    if not os.path.exists(SLAVE_LOGS_PATH):
        open(SLAVE_LOGS_PATH, 'w', encoding='utf-8', errors='replace').close()


def print_logs(text):
    if SHOW_PRINT_MSG:
        with open(SLAVE_LOGS_PATH, 'a', encoding='utf-8', errors='replace') as dfw:
            dfw.write("\n"+str(text).replace("\n", " 'new line' "))
            dfw.close()


if SHOW_PRINT_MSG:
    with open(SLAVE_LOGS_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
        dfw.write("Slave logs\n" +
                  "Fecha: "+str(datetime.date.today()))
        dfw.close()


class WsEvents(Websocket):

    SERVER_AWAIT_TIME = AWAIT_TIME
    DESCONECTION_MAX_TIME = AWAIT_TIME_FROM_LAST_MESSAGE
    MASTER_PORT = SERVER_PORT

    def onLoop(self):
        with open(SEND_FLAG_PATH, 'r', encoding='utf-8', errors='replace') as ff:
            text = ff.read()
            ff.close()
            if text == "3" or (text != "" and time.time()-os.path.getmtime(SEND_FLAG_PATH) > 3):
                print_logs("[SERVER]= Error, closed for strange desconection")
                with open(SEND_FLAG_PATH, 'w', encoding='utf-8', errors='replace') as ffw:
                    ffw.write("3")
                    ffw.close()
                self.close()
            elif(int(time.time())-self.LAST_MESSAGE_TIME <= self.DESCONECTION_MAX_TIME):
                if text == "1":
                    try:
                        with open(SEND_DATA_PATH, 'r', encoding='utf-8', errors='replace') as df:
                            ticketsPack = ""
                            dataList = df.read().strip().split('\n')
                            df.close()
                            ReadLine = 0
                            while(ReadLine < len(dataList)):
                                header = dataList[ReadLine].split('.')
                                ReadLine = ReadLine+1
                                data = dataList[ReadLine:ReadLine +
                                                int(header[2])]
                                ReadLine = ReadLine+int(header[2])+1
                                if(header[1] == "delTickets"):
                                    for i, ticket in enumerate(data):
                                        ticketsPack += ticket+"\n"
                                        if i == len(data)-1:
                                            self.broadcast(json.dumps(
                                                {'type': 'delTickets', 'status': '1'})+'////\n'+ticketsPack)
                                            ticketsPack = ""
                                        elif len(ticketsPack.encode('utf-8')) >= MAX_PACKAGE_BYTES_SIZE:
                                            self.broadcast(json.dumps(
                                                {'type': 'delTickets', 'status': '0'})+'////\n'+ticketsPack)
                                            ticketsPack = ""
                                            time.sleep(AWAIT_PACKAGE_TIME)
                                elif(header[1] == "authTicket"):
                                    with open(RECIVED_DATA_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
                                        dfw.write("")
                                        dfw.close()
                                    with open(RECIVED_FLAG_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
                                        dfw.write("")
                                        dfw.close()
                                    if len(header) < 5:
                                        self.broadcast(json.dumps(
                                            {'type': 'authTicket', 'status': '1'})+'////\n'+"\n".join(data))
                                    else:
                                        self.broadcast(json.dumps(
                                            {'type': 'authTicket', 'status': '1', 'direction': header[4]})+'////\n'+"\n".join(data))

                                    ticketsPack = ""
                                elif(header[1] == "buttonExit"):
                                    self.broadcast(json.dumps(
                                        {'type': 'buttonExit', 'status': '1'})+'////\n'+"\n".join(data))
                                    ticketsPack = ""
                                time.sleep(self.SERVER_AWAIT_TIME)

                        with open(SEND_FLAG_PATH, 'w', encoding='utf-8', errors='replace') as ffw:
                            ffw.write("2")
                            ffw.close()
                    except:
                        self.onError()
            else:
                if(text != "3"):
                    with open(SEND_FLAG_PATH, 'w', encoding='utf-8', errors='replace') as ffw:
                        ffw.write("3")
                        ffw.close()
                    print_logs("[SERVER]= Close conection for inactivity")
                    self.close()

    def onMessage(self, message):
        req = message.split("////\n")  # req[0]=headers, req[1]=body
        headerJson = json.loads(req[0])
        if headerJson["type"] == "updateDevice":
            while True:
                with open(RECIVED_FLAG_PATH, 'r', encoding='utf-8', errors='replace') as ff:
                    flagState = ff.read()
                    ff.close()
                    if flagState == "" or int(time.time())-self.LAST_MESSAGE_TIME >= self.DESCONECTION_MAX_TIME:
                        try:
                            accessList = requests.get(
                                url="http://"+self.addr[0]+":"+str(self.MASTER_PORT)+"/scannersPetition", params={"scannerAccessKey": req[1]}, timeout=1)
                            accessList.raise_for_status()
                        except:
                            self.close()
                            break
                        with open(RECIVED_DATA_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
                            dfw.write(
                                "header.currentTickets."+str(headerJson["size"][0])+"\n"+accessList.json()["tickets"])
                            dfw.close()
                        with open(RECIVED_FLAG_PATH, 'w', encoding='utf-8', errors='replace') as ffw:
                            ffw.write("1")
                            ffw.close()
                        break
                    time.sleep(self.SERVER_AWAIT_TIME)
        elif headerJson["type"] == "delTickets" or headerJson["type"] == "newTickets" or headerJson["type"] == "authTicket":
            while True:
                with open(RECIVED_FLAG_PATH, 'r', encoding='utf-8', errors='replace') as ff:
                    flagState = ff.read()
                    ff.close()
                    if flagState == "" or int(time.time())-self.LAST_MESSAGE_TIME >= self.DESCONECTION_MAX_TIME:
                        with open(RECIVED_DATA_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
                            dfw.write(
                                "header."+headerJson["type"]+"."+str(headerJson["size"])+"\n"+req[1])
                            dfw.close()
                        with open(RECIVED_FLAG_PATH, 'w', encoding='utf-8', errors='replace') as ffw:
                            ffw.write("1")
                            ffw.close()
                        break
                    elif flagState == "0":
                        with open(RECIVED_DATA_PATH, 'a', encoding='utf-8', errors='replace') as dfw:
                            dfw.write(req[1])
                            dfw.close()
                        break
                    else:
                        time.sleep(self.SERVER_AWAIT_TIME)
            with open(RECIVED_FLAG_PATH, 'w', encoding='utf-8', errors='replace') as ffw:
                ffw.write(headerJson["status"])
                ffw.close()
        elif headerJson["type"] == "recived":
            while True:
                with open(SEND_FLAG_PATH, 'r', encoding='utf-8', errors='replace') as ff:
                    flagState = ff.read()
                    ff.close()
                    if flagState == "2" or int(time.time())-self.LAST_MESSAGE_TIME >= self.DESCONECTION_MAX_TIME:
                        with open(SEND_DATA_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
                            dfw.write("")
                            dfw.close()
                        with open(SEND_FLAG_PATH, 'w', encoding='utf-8', errors='replace') as ffw:
                            ffw.write("")
                            ffw.close()
                        break
                    else:
                        time.sleep(self.SERVER_AWAIT_TIME)
        else:
            pass
        self.LAST_MESSAGE_TIME = int(time.time())

    def onConnect(self):
        print_logs("[SERVER]= New connection, total connection:" +
                   str(len(self.connections)))
        if len(self.connections) > 1:
            with open(SEND_FLAG_PATH, 'w', encoding='utf-8', errors='replace') as ffw:
                ffw.write("3")
                ffw.close()
            conns = list(iter(self.connections))
            for i in range(len(conns)):
                if i < len(conns)-1:
                    conns[i].close()
        if not os.path.exists(DB_DIR_NAME):
            os.makedirs(DB_DIR_NAME)
        if not os.path.exists(SEND_FLAG_PATH):
            open(SEND_FLAG_PATH, 'w', encoding='utf-8', errors='replace').close()
        if not os.path.exists(SEND_DATA_PATH):
            open(SEND_DATA_PATH, 'w', encoding='utf-8', errors='replace').close()
        if not os.path.exists(RECIVED_FLAG_PATH):
            open(RECIVED_FLAG_PATH, 'w',
                 encoding='utf-8', errors='replace').close()
        if not os.path.exists(RECIVED_DATA_PATH):
            open(RECIVED_DATA_PATH, 'w',
                 encoding='utf-8', errors='replace').close()

        with open(RECIVED_DATA_PATH, 'w', encoding='utf-8', errors='replace') as dfw:
            dfw.write("")
            dfw.close()

        with open(SEND_FLAG_PATH, 'r', encoding='utf-8', errors='replace') as ff:
            if ff.read() != "":
                with open(SEND_DATA_PATH, 'r', encoding='utf-8', errors='replace') as df:
                    ticketsPack = ""
                    text = df.read()
                    ticketList = text.split('\n')[1:]
                    file_text = text.replace(" ", "").replace("\n", "")
                    df.close()
                    if(file_text != ""):
                        with open(SEND_FLAG_PATH, 'w', encoding='utf-8', errors='replace') as ffw:
                            ffw.write("2")
                            ffw.close()
                        time.sleep(self.SERVER_AWAIT_TIME)
                        for i, ticket in enumerate(ticketList):
                            ticketsPack += ticket+"\n"
                            if (i == len(ticketList)-1):
                                self.broadcast(json.dumps(
                                    {'type': 'delTickets', 'status': '1'})+'////\n'+ticketsPack)
                                ticketsPack = ""
                            elif (len(ticketsPack.encode('utf-8')) >= MAX_PACKAGE_BYTES_SIZE):
                                self.broadcast(json.dumps(
                                    {'type': 'delTickets', 'status': '0'})+'////\n'+ticketsPack)
                                ticketsPack = ""
                                time.sleep(AWAIT_PACKAGE_TIME)
                    else:
                        with open(SEND_FLAG_PATH, 'w', encoding='utf-8', errors='replace') as ffw:
                            ffw.write("")
                            ffw.close()

            ff.close()
        self.broadcast(json.dumps({'type': 'update', 'status': '1'}))
        self.LAST_MESSAGE_TIME = int(time.time())

    def onDisconnect(self):
        with open(SEND_FLAG_PATH, 'w', encoding='utf-8', errors='replace') as ffw:
            ffw.write("3")
            ffw.close()
        print_logs('[SERVER]= Closed conection from'+str(self.addr))

    def onError(self):
        with open(SEND_FLAG_PATH, 'w', encoding='utf-8', errors='replace') as ffw:
            ffw.write("3")
            ffw.close()
        try:
            self.close()
        except:
            pass
        print_logs('[SERVER]= Closed conection from'+str(self.addr))


with open(SEND_FLAG_PATH, 'w', encoding='utf-8', errors='replace') as ffw:
    ffw.write("3")
    ffw.close()


server = WebsocketServer("0.0.0.0", SLAVE_PORT, 2,
                         WsEvents, print_logs)
server.run()
