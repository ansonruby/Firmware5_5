#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Libreria personal validar con expreciones regulares











"""
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------

#---------------------------------------------------------------------------------------
#                                   importar complementos
#---------------------------------------------------------------------------------------

import re

#---------------------------------------------------------------------------------------
#                                  Formatos de qr fusepong con expreciones regulares
#---------------------------------------------------------------------------------------

TIPO_1_1_QR_F   = '-[\w=+/]{80,150}\.[\w=+/]{1,80}'
TIPO_1_QR_F     = '[\w=+/]{80,150}\.[\w=+/]{1,80}'
TIPO_2_QR_F     = '[\w=+/]{1,150}\.[\w=+/]{1,150}\.\d{12,14}'
TIPO_2_1_QR_F   = '[\w=+/]{1,150}\.[\w=+/]{1,150}\.\d{12,14}\.\d{12,14}'
TIPO_3_QR_F     = '3\.[\w=+/]{1,80}\.[\w=+/]{1,80}\.\d{1,3}\.\d{12,14}'
TIPO_3_Ne_QR_F  = '3\.[\w=+/]{1,80}\.[\w=+/]{1,80}\.[\d-]{1,3}\.\d{12,14}'

#-----------------------------------------------------------------------------------------
#           Formato 1 :         azAZ09. azAZ09                  -> sha256.id  si exite el ID entra
#-----------------------------------------------------------------------------------------
#           Formato 2 :         azAZ09. azAZ09. 09              -> sha256.id.tiempo ventana quemado 60 minutos
#-----------------------------------------------------------------------------------------
#           Formato 2.1 :       azAZ09. azAZ09. 09. 09          -> sha256.id.tiempo init.tiempo fin.
#-----------------------------------------------------------------------------------------
#           Formato 3 :         3. azAZ09. azAZ09. azAZ09. 09  -> tipo.id.id.id.tiempo init.   tiken multiples Usuarios
#-----------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------
#                                   Funciones para el manejo de archivos
#---------------------------------------------------------------------------------------

def Validar_QR_Fusepong(Dato):

    if      re.match(TIPO_2_1_QR_F, Dato):      return 'T2_1'
    elif    re.match(TIPO_2_QR_F, Dato):        return 'T2'
    elif    re.match(TIPO_1_1_QR_F, Dato):      return 'T1_1'
    elif    re.match(TIPO_1_QR_F, Dato):        return 'T1'
    elif    re.match(TIPO_3_QR_F, Dato):        return 'T3'
    elif    re.match(TIPO_3_Ne_QR_F, Dato):     return 'T3-'
    #elif    re.match(TIPO, Dato):    return 'T'
    else:                                   return ''






#---------------------------------------------------------------------------------------
#                                   Test de exprecones regulares
#---------------------------------------------------------------------------------------
"""
codigos = [ '3.djhd', 'aaa111', 'aab11', 'aaa1111', 'aaz1', 'aaa','anderson',
            'a1234243', '123123', '3.djhdasdshfg.',
            'vnsGvGR/yTXKto+AiBnqeeoklrQUvpb3oz/GoY3bGknWTWqNsknRmpyRrSbLs0KJip6LRCUPxjdGCqA6fR+Vdw==.h2',
            'QN12RyqIbsVqfgjGiik6Z1r2LeoiaPs+ZG3jLS8OG9KKdixmJszyQl+wlf/kXBvnonV4hiZoPQID+d4+4b1zlA==.h2',
            'yYFRnkMEgoTFQVSVSJDBHhNCUiVc14cFM5bQgXFlOf1Wokz9C6EXNaXcc2joX2PeIeC74XTQzqmhTuw9PMit4w==.g27d4',
            '<3.L2M1Ws7wbbWhqNWaKp5LPA==.x4OmKNnzazeGWY4OLCcqaQ==.5.1643838928816>',
            '3.L2M1Ws7wbbWhqNWaKp5LPA==.x4OmKNnzazeGWY4OLCcqaQ==.5.1643838928816',
            '3.L2M1Ws7wbbWhqNWaKp5LPA==.x4OmKNnzazeGWY4OLCcqaQ==.-5.1643838928816',
            '3.L2M1Ws7wbbWhqNWaKp5LPA==.x4OmKNnzazeGWY4OLCcqaQ==.5.',
            '3.L2M1Ws7wbbWhqNWaKp5LPA==.x4OmKNnzazeGWY4OLCcqaQ==.5',
            '3.L2M1Ws7wbbWhqNWaKp5LPA==.x4OmKNnzazeGWY4OLCcqaQ==.',
            '3.L2M1Ws7wbbWhqNWaKp5LPA==.x4OmKNnzazeGWY4OLCcqaQ==',
            '3.L2M1Ws7wbbWhqNWaKp5LPA==.',
            'https://www.kaspersky.com',
            'https://www.imaginads.app/imaginadsQR/landing/Rs7TFe6UDVi3lWI5zyIn',
            'https://python-para-impacientes.blogspot.com/2014/02/expresiones-regulares.html',
            'http://codexexempla.org/articulos/2008/exp_regulares_1.php',
            'smsto:555-555-5555:Generador de Codigos QR de TEC-IT',
            '3.L2M1Ws7wbbWhqNWaKp5LPA==.2345.5.1643838928816',
            '4.L2M1Ws7wbbWhqNWaKp5LPA==.x4OmKNnzazeGWY4OLCcqaQ==.5.1643838928816',
            '.L2M1Ws7wbbWhqNWaKp5LPA==.x4OmKNnzazeGWY4OLCcqaQ==.5.1643838928816',
            '33.L2M1Ws7wbbWhqNWaKp5LPA==.x4OmKNnzazeGWY4OLCcqaQ==.5.1643838928816',
            'L2M1Ws7wbbWhqNWaKp5LPA==.x4OmKNnzazeGWY4OLCcqaQ==.1643838928816',
            'L2M1Ws7wbbWhqNWaKp5LPA==']

"""

"""

for elemento in codigos:
    if re.match('aa[a-z]1{2,}', elemento):
        print(elemento)  # aaa111 , aab11, aaa1111
print 'otra manera'
for elemento in codigos:
    if re.match('a+1+', elemento):
        print(elemento)  # aaa111 , aaa1111
print 'Numeros'
for elemento in codigos:
    if re.match('^[0-9,$]*$', elemento):
        print(elemento)
print 'Letras'
for elemento in codigos:
    if re.match(r'^[A-Za-z]+$', elemento):
        print(elemento)
print 'Formato'
for elemento in codigos:
    if re.match('\d\.[\w=+]{1,30}\.[\w=+]{1,30}\.\d{1,4}\.\d{1,14}', elemento):#\d\.[\w\.=+]{1,30}\.
        print(elemento)


print 'Tipo 1'
for elemento in codigos:
    if re.match('[\w=+/]{80,150}\.[\w=+/]{1,80}', elemento):#\d\.[\w\.=+]{1,30}\.
        print(elemento)
print 'Tipo 2'
for elemento in codigos:
    if re.match('[\w=+/]{1,150}\.[\w=+/]{1,150}\.\d{12,14}', elemento):#\d\.[\w\.=+]{1,30}\.
        print(elemento)
print 'Tipo 3'
for elemento in codigos:
    if re.match('3\.[\w=+/]{1,30}\.[\w=+/]{1,30}\.\d{1,4}\.\d{12,14}', elemento):#\d\.[\w\.=+]{1,30}\.
        print(elemento)
print 'Tipo 3 con negativos'
for elemento in codigos:
    if re.match('3\.[\w=+/]{1,30}\.[\w=+/]{1,30}\.[\d-]{1,4}\.\d{12,14}', elemento):#\d\.[\w\.=+]{1,30}\.
        print(elemento)
"""

"""
for elemento in codigos:
    Validacion = Validar_QR_Fusepong(elemento)
    if  Validacion != '':
        print Validacion +' : '+ elemento
"""
