#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Libreria personal para la generacion de pines segun su usuario.











"""
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------
#                                   importar complementos
#---------------------------------------------------------------------------------------

from datetime import datetime
from datetime import timedelta

#---------------------------------------------------------------------------------------
#                                   Librerias personale
#---------------------------------------------------------------------------------------

from Lib_File import *                              # importar con los mismos nombres
from Lib_Rout import *                              # importar con los mismos nombres
from Lib_Encryp import *                            # importar con los mismos nombres

#---------------------------------------------------------------------------------------
#                                   Funciones
#---------------------------------------------------------------------------------------

#---------------------------------------------------------------------------------------
#---------------------------------
#           Generador de pines
#---------------------------------
#---------------------------------------------------------------------------------------

def Generador_Pines(N_PINES, Archivo_Usuarios, Archivo_Destino):
    Usuarios    = Get_File(Archivo_Usuarios)
    Key         = Get_File(KEY_DISPO)

    now = datetime.now()
    Fecha = now.strftime('%Y%m%d')

    #Fecha ='20200225'
    #print Key
    #print Fecha

    Clear_File(Archivo_Destino)

    for linea in Usuarios.split('\n'):
        if len (linea) >5 :
            Lista_Pines =''
            linea = linea.split('.')
            ID= linea[0].rstrip('\r')
            Rut_MD5 = linea[1].rstrip('\r')

            for x in  range(N_PINES):
                if x == 0   : Resualtado = MD5(Key + Rut_MD5+ Fecha)
                else        : Resualtado = MD5(Resualtado)
                #print 'MD5:' + Resualtado
                Numeros =''
                contador =0
                for letra in Resualtado:
                    if letra.isalpha() == False:
                        Numeros += letra
                contador =0
                N_Salto =''
                #print Numeros
                inv_numeros = Numeros[::-1] # invertir lista de nuemros
                #print inv_numeros
                for Numero in inv_numeros:
                    if contador%2 == 0 :
                        N_Salto += Numero
                    contador = contador + 1

                if len (N_Salto[0:4]) > 3:
                    Lista_Pines = Lista_Pines + '.'+ N_Salto[0:4]
                else:
                    N_Salto += '9999'
                    Lista_Pines = Lista_Pines + '.'+ N_Salto[0:4]
                    #print 'numero de faltantes'

            cadena = ID + Lista_Pines  # +'\n'
            #print cadena
            Add_File(Archivo_Destino, cadena + '\n')
            #"Escrivir_Archivo(cadena,26)

    print 'pines listos'



Generador_Pines(4, TAB_USER_TIPO_1, TAB_PINES_TIPO_1)
