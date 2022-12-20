
N_A_ID_Lector           ='/home/pi/.ID/Datos_Creacion.txt'
#-------        Data     ----------
N_A_Servidor		='/home/pi/Firmware/db/Data/Tabla_Servidor.txt'
N_A_Lector		='/home/pi/Firmware/db/Data/Tabla_Lector.txt'
N_A_Tabla_Enviar	='/home/pi/Firmware/db/Data/Tabla_Enviar.txt'

#-------        Status     ----------

N_A_Estados_Led	        ='/home/pi/Firmware/db/Status/Estado_Led.txt'
N_A__Led	        ='/home/pi/Firmware/db/Status/Led.txt'

N_A_Estados_Teclado     ='/home/pi/Firmware/db/Status/Estado_Teclado.txt'
N_A_Teclas_Led	        ='/home/pi/Firmware/db/Status/Teclas.txt'

N_A_Estados_Chicharra   ='/home/pi/Firmware/db/Status/Estado_Chicharra.txt'

N_A_QR                  ='/home/pi/Firmware/db/Status/QR.txt'
N_A_Estados_QR          ='/home/pi/Firmware/db/Status/Estado_QR.txt'
N_A_Estados_Sensor      ='/home/pi/Firmware/db/Status/Estado_Sensor.txt'
N_A_Estados_QR_Repe     ='/home/pi/Firmware/db/Status/Estado_QR_Repetido.txt'

#-------        Log     ----------

N_A_QR_Numero_Lecturas  ='/home/pi/Firmware/db/Log/Numero_Lecturas_QR.txt'
N_A_Numero_Reinicios    ='/home/pi/Firmware/db/Log/Numero_Reinicios.txt'

#-------        Config     ----------

N_A_Direccion_Torniqute  ='/home/pi/Firmware/db/Config/Direccion_Torniquete.txt'

#-------        Actualizador     ----------
N_A_Procedimiento       ='/home/pi/Actualizador/db/Respuesta_Peticion_Firmware.txt'
N_A_Procesos            ='/home/pi/Firmware/auto/Procesos.txt'
N_A_Vercion_Firmware    ='/home/pi/Firmware/db/Config/Vercion_Firmware.txt'
N_A_ProcesosBK          ='/home/pi/Firmware/auto/ProcesosBK.txt' # cambiar a la ruta del proceso de BK
N_A_Memoria_Actualizador='/home/pi/Actualizador/db/Memoria_Actualizador.txt'

N_A_Estado_Actualizador ='/home/pi/Actualizador/db/Estado_Actualizador.txt'



def Generar_ID_Tarjeta(MAC): #mejorar por que podia pasa cualquiera
        global N_A_ID_Lector

        Caracte         = ''
        Fecha_Init      = ''
        Consecutivo     = ''

        Contador=0
        
        archivo = open(N_A_ID_Lector, 'r')
        archivo.seek(0)
        for linea in archivo.readlines():
                s=linea.rstrip('\n')
                s=s.rstrip('\r')
                #s2 =s.partition(".")
                #print 'ID: '+ s2[0] + ' RUT: '+s2[2]
                if Contador == 0:  Caracte=s
                if Contador == 1:  Fecha_Init=s
                if Contador == 2:  Consecutivo=s
		
                #print s
                Contador+=1
		
        archivo.close()
	
        return Caracte+Fecha_Init+MAC+Consecutivo

def Get_archivo(a):
        
    global N_A_Servidor
    global N_A_Lector
    global N_A_Tabla_Enviar
    global N_A_Estados_Led
    global N_A_Estados_Teclado
    global N_A_Teclas_Led
    global N_A_Estados_Chicharra
    global N_A_QR
    global N_A_Estados_QR
    global N_A_Estados_Sensor
    global N_A__Led
    global N_A_Estados_QR_Repe
    global N_A_QR_Numero_Lecturas
    global N_A_Direccion_Torniqute
    global N_A_Numero_Reinicios
    global N_A_Procedimiento
    global N_A_Procesos
    global N_A_Vercion_Firmware
    global N_A_ProcesosBK
    global N_A_Memoria_Actualizador
    global N_A_Estado_Actualizador
	
    arch = ''
	
    if a==0:	arch	=	N_A_Servidor
    if a==1:	arch	=	N_A_Lector
    if a==2:	arch	=	N_A_Tabla_Enviar
    if a==3:	arch	=	N_A_Estados_Led
    if a==4:	arch	=	N_A_Estados_Teclado
    if a==5:	arch	=	N_A_Teclas_Led
    if a==6:	arch	=	N_A_Estados_Chicharra
    if a==7:	arch	=	N_A_QR
    if a==8:	arch	=	N_A_Estados_QR
    if a==9:	arch	=	N_A_Estados_Sensor
    if a==10:	arch	=	N_A__Led
    if a==11:	arch	=	N_A_Estados_QR_Repe
    if a==12:	arch	=	N_A_QR_Numero_Lecturas
    if a==13:	arch	=	N_A_Direccion_Torniqute
    if a==14:	arch	=	N_A_Numero_Reinicios
    if a==15:	arch	=	N_A_Procedimiento
    if a==16:	arch	=	N_A_Procesos
    if a==17:	arch	=   N_A_Vercion_Firmware
    if a==18:	arch	=   N_A_ProcesosBK
    if a==19:	arch	=   N_A_Memoria_Actualizador
    if a==20:	arch	=   N_A_Estado_Actualizador
    return arch


def Borrar_Archivo(a):
        
	arch = Get_archivo(a)
	archivo = open(arch, "w")
	archivo.write("")
	archivo.close()

def Leer_Archivo(a):
        
        arch = Get_archivo(a)	
	f = open (arch,'r')
	mensaje = f.read()
	#print(mensaje)
	f.close()
	return mensaje 

def Leer_Estado(a):

	arch = Get_archivo(a)
	f = open (arch,'r')
	mensaje = f.read()
	#print(mensaje)
	f.close()
	return mensaje

def Escrivir_Estados(Texto, a):
        
        arch = Get_archivo(a)
        archivo = open(arch, "w")
        #print(archivo.tell())
        archivo.write(Texto)
        #print(archivo.tell())
        archivo.close()

def Escrivir_Archivo(Texto,a):
        
        arch = Get_archivo(a)
        archivo = open(arch, "a")
        #print(archivo.tell())
        archivo.write(Texto + "\n")
        #print(archivo.tell())
        archivo.close()

def Leer_Led():
	global N_A_Estados_Led
	f = open (N_A_Estados_Led,'r')
	mensaje = f.read()
	#print(mensaje)
	f.close()
	return mensaje 	

def Leer():
	global N_A_Tabla_Enviar
	f = open (N_A_Tabla_Enviar,'r')
	mensaje = f.read()
	#print(mensaje)
	f.close()
	return mensaje 

def Verificar_ID(Pal): #mejorar por que podia pasa cualquiera
	global N_A_Servidor

	archivo = open(N_A_Servidor, 'r')
	archivo.seek(0)
	for linea in archivo.readlines():
		s=linea.rstrip('\n')
		s=s.rstrip('\r')
		s2 =s.partition(".")
		#print 'ID: '+ s2[0] + ' RUT: '+s2[2]
		Rut = s2[0]
		if 	Rut ==	Pal:
			archivo.close()	
			return s2[0]
	archivo.close()	
	return -1

def ID(Pal): #mejorar por que podia pasa cualquiera
	global N_A_Servidor
	
	archivo = open(N_A_Servidor, 'r')
	
	archivo.seek(0)
	for linea in archivo.readlines():
		s=linea.rstrip('\n')
		s=s.rstrip('\r')
		s2 =s.partition(".")
		#print 'ID: '+ s2[0] + ' RUT: '+s2[2]
		Rut = s2[2]
		if 	Rut ==	Pal:
			archivo.close()
			return s2[0]
	
	archivo.close()
	return -1

def Verificar_acceso(ID1): #mejorar por que podia pasa cualquiera
	global	N_A_Lector
	Contador=0
	archivo = open(N_A_Lector, 'r')
	archivo.seek(0)
	for linea in archivo.readlines():
		s=linea.rstrip('\n')
		s2 =s.partition(".")
		s3 = s2[2].partition(".")
		#print 'QR: '+ s2[0] + ' ID: '+s3[0]
		ID2 = s3[0]
		if 	ID2 ==	ID1:
			Contador +=1
	archivo.close()	
	return Contador

def Escrivir_Enviar(Texto):
	global N_A_Tabla_Enviar
	archivo = open(N_A_Tabla_Enviar, "a")
	#print(archivo.tell())
	archivo.write(Texto + "\n")
	#print(archivo.tell())
	archivo.close()
	
def Escrivir(Texto):
	global N_A_Lector
	archivo = open(N_A_Lector, "a")
	#print(archivo.tell())
	archivo.write(Texto + "\n")
	#print(archivo.tell())
	archivo.close()

def Escrivir_nuevo(a, Texto):
	global N_A_Servidor
	global N_A_Lector
	global N_A_Tabla_Enviar
	
	Entrada=''
	if a==0:	arch	=	N_A_Servidor
	if a==1:	arch	=	N_A_Lector
	if a==2:	arch	=	N_A_Tabla_Enviar
	
	if a != 2: Entrada = Texto + "\n"
	
	archivo = open(arch, "w")
	archivo.write(Entrada)
	archivo.close()

def Estado_Usuario(Pal,P_I):

	if P_I == 0:
		ID_1 = ID(Pal)
	else:
		ID_1 = Verificar_ID(Pal)
		#ID_1 = Pal
	
	N_veri = Verificar_acceso(ID_1)

	
	#print 'ID: '
	#print ID_1
	#print 'Veces: '
	#print N_veri
	if N_veri != 0:
		if N_veri % 2 == 0	:	N_veri = 1 # Entrar
		else				:	N_veri = 2 # Salir
		
	if ID_1 == -1 and  N_veri == 0:					return ID_1, 'Denegado'		   #print 'NO existe'
	if ID_1 != -1 and  N_veri == 0 or N_veri == 1:	return ID_1, 'Access granted-E'#print 'Entrada'
	if ID_1 != -1 and  N_veri == 2:					return ID_1, 'Access granted-S'#print 'Salida'
	

	
	
