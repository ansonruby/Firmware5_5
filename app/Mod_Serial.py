#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor:  Luding Castaneda,
        Anderson Amaya Pulido






# ideas a implementar




# dmesg | grep tty
"""
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------



#---------------------------------
#           Librerias personales
#---------------------------------
from lib.Lib_settings import *  # importar con los mismos nombres
from lib.Fun_Mod_Serial import *  # importar con los mismos nombres


#---------------------------------
#           Configuraciones de lectoras
#---------------------------------

VECTOR_LECTORAS = []
data = Get_Lectoras()

for Lectora in data:
    try:
        #print Lectora['Puerto'], Lectora['Nombre'], Lectora['Locacion']
        VECTOR_LECTORAS.append(LECTORAS (Lectora['Puerto'], Lectora['Nombre'], Lectora['Locacion']))
    except:
        print 'Key Error no definidas'


for Lectora in VECTOR_LECTORAS:
    Lectora.Inicio_Lectora()


#---------------------------------
#           pruebas
#---------------------------------
#LECTORA_1 = LECTORAS ('0', 'QR600-VHK-E','0')
#LECTORA_2 = LECTORAS ('1', 'QR600-VHK-E','0')
#LECTORA_1.Inicio_Lectora()
#LECTORA_2.Inicio_Lectora()
