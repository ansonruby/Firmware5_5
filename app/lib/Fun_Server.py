#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Libreria personal para procesar un qr.




# ideas a implementar





"""
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
#---------------------------------
#           Librerias personales
#---------------------------------

from lib.Lib_File import *            # importar con los mismos nombres
from lib.Lib_Rout import *            # importar con los mismos nombres


#---------------------------------------------------------
#----       funciones de uso comun para peticiones al servidor
#---------------------------------------------------------

def Get_Rout_server():#Mejor_Opcion_link

    opciones    = Get_File(CONF_M_CONEX_SERVER)
    IP_Ser      = Get_File(CONF_IP_SERVER)
    Domi_Ser    = Get_File(CONF_DOMI_SERVER)

    # return 'http://192.168.104.160:3000'
    # return 'http://34.221.7.202'
    #print opciones
    #print Domi_Ser
    #print IP_Ser
    if opciones == '0':    return 'http://' + IP_Ser     #Mensajes('Test 0 Error, http Dominio NO, IP NO; https Dominio NO, IP NO.','Error')
    if opciones == '1':    return 'http://' + Domi_Ser  #Mensajes('Test 25%  OK, http Dominio OK, IP NO; https Dominio NO, IP NO.','OK')
    if opciones == '10':   return 'http://' + IP_Ser    #Mensajes('Test 25%  OK, http Dominio NO, IP OK; https Dominio NO, IP NO.','OK')
    if opciones == '11':   return 'http://' + IP_Ser    #Mensajes('Test 50%  OK, http Dominio OK, IP OK; https Dominio NO, IP NO.','OK')

    if opciones == '100':  return 'https://' + IP_Ser   #Mensajes('Test 25%  OK, http Dominio NO, IP NO; https Dominio NO, IP OK.','OK')
    if opciones == '101':  return 'https://' + IP_Ser   #Mensajes('Test 50%  OK, http Dominio OK, IP NO; https Dominio NO, IP OK.','OK')
    if opciones == '110':  return 'https://' + IP_Ser   #Mensajes('Test 50%  OK, http Dominio NO, IP OK; https Dominio NO, IP OK.','OK')
    if opciones == '111':  return 'https://' + IP_Ser   #Mensajes('Test 75%  OK, http Dominio OK, IP OK; https Dominio NO, IP OK.','OK')

    if opciones == '1000': return 'https://' + Domi_Ser #Mensajes('Test 25%  OK, http Dominio NO, IP NO; https Dominio OK, IP NO.','OK')
    if opciones == '1001': return 'https://' + Domi_Ser #Mensajes('Test 50%  OK, http Dominio OK, IP NO; https Dominio OK, IP NO.','OK')
    if opciones == '1010': return 'http://' + IP_Ser    #Mensajes('Test 50%  OK, http Dominio NO, IP OK; https Dominio OK, IP NO.','OK')
    if opciones == '1011': return 'http://' + IP_Ser    #Mensajes('Test 75%  OK, http Dominio OK, IP OK; https Dominio OK, IP NO.','OK')

    if opciones == '1100': return 'https://' + IP_Ser   #Mensajes('Test 50%  OK, http Dominio NO, IP NO; https Dominio OK, IP OK.','OK')
    if opciones == '1101': return 'https://' + IP_Ser   #Mensajes('Test 75%  OK, http Dominio OK, IP NO; https Dominio OK, IP OK.','OK')
    if opciones == '1110': return 'https://' + IP_Ser   #Mensajes('Test 75%  OK, http Dominio NO, IP OK; https Dominio OK, IP OK.','OK')
    if opciones == '1111': return 'https://' + IP_Ser   #Mensajes('Test 100% OK, http Dominio OK, IP OK; https Dominio OK, IP OK.','OK')
