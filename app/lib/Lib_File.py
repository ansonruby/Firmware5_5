#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
"""

Autor: Anderson Amaya Pulido

Libreria personal para manejo de archivos de texto.
1)  manejo y busqueda de linea como base de Datos










"""
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------
#                                   importar complementos
#---------------------------------------------------------------------------------------

import os

#---------------------------------------------------------------------------------------
#                                   Funciones para el manejo de archivos
#---------------------------------------------------------------------------------------

#---------------------------------------------------------------------------------------
#                   Manejo de archivos Total
#---------------------------------------------------------------------------------------
def Clear_File(arch):
    if os.path.exists(arch):
        archivo = open(arch, "w")
        archivo.write("")
        archivo.close()
#---------------------------------------------------------------------------------------
def Get_File(arch):
    mensaje = ""
    if os.path.exists(arch):
        f = open (arch,'r')
        mensaje = f.read()
        #print(mensaje)
        f.close()
        return mensaje
    else:
        return mensaje
#---------------------------------------------------------------------------------------
def Set_File(arch, Text):
    if os.path.exists(arch):
        archivo = open(arch, "w")
        archivo.write(Text)
        archivo.close()
#---------------------------------------------------------------------------------------
def Add_File(arch, Text):
    if os.path.exists(arch):
        archivo = open(arch, "a")
        archivo.write(Text)
        archivo.close()
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
#                   Manejo del archivo por lineas
#---------------------------------------------------------------------------------------
def Get_Line(arch, Numero):# comienza en 1
    if os.path.exists(arch):
        f = open (arch,'r')
        lineas = f.readlines()
        f.close()
        return lineas[Numero-1] # revisar si comensar en 1 o 0
    else:
        return ""
#---------------------------------------------------------------------------------------
def Clear_Line(arch, Numero):# comienza en 1
    if os.path.exists(arch):
        f = open (arch,'r')
        lineas = f.readlines()
        f.close()
        lineas.pop(Numero-1)
        #print lineas
        f2 =open(arch, "w")
        f2.write(''.join(lineas) )
        f2.close()
#---------------------------------------------------------------------------------------
def Update_Line(arch, Numero, Dato): # comienza en 1, incluir el/n
    if os.path.exists(arch):
        f = open (arch,'r')
        lineas = f.readlines()
        f.close()
        lineas[Numero-1]= Dato
        f2 =open(arch, "w")
        f2.write(''.join(lineas) )
        f2.close()
#---------------------------------------------------------------------------------------
def Add_Line_End(arch, Dato): #incluir el/n
    if os.path.exists(arch):
        f = open (arch,'r')
        lineas = f.readlines()
        f.close()
        f2 =open(arch, "w")
        f2.write(''.join(lineas) )
        f2.write(Dato)
        f2.close()
#---------------------------------------------------------------------------------------
def Add_Line_Pos(arch, Numero, Dato): #incluir el/n
    if os.path.exists(arch):
        f = open (arch,'r')
        lineas = f.readlines()
        f.close()
        inicio = lineas[0:(Numero-1)]
        fin = lineas[(Numero-1):]

        f2 =open(arch, "w")
        f2.write(''.join(inicio) )
        f2.write(Dato)
        f2.write(''.join(fin) )
        f2.close()
#---------------------------------------------------------------------------------------
def Num_lines(arch):
    if os.path.exists(arch):
        f = open (arch,'r')
        lineas = f.readlines()
        f.close()
        return len(lineas)
    else:
        return -1



#---------------------------------------------------------------------------------------
#-----------------------------------------------------------
#                       RESUMEN y descripciones
#-----------------------------------------------------------
#---------------------------------------------------------------------------------------

#---------------------------------------------------------------------------------------
#                   Manejo del archivo Generales
#---------------------------------------------------------------------------------------

# Clear_File(arch)              # Borrar todo el archivo
# Get_File(arch)                # Leer todo el archivo
# Set_File(arch, Text)          # Resplazar todo el archivo
# Add_File(arch, Text)          # agragar texto al archivo

#---------------------------------------------------------------------------------------
#                   Manejo del archivo por lineas
#---------------------------------------------------------------------------------------

# Get_Line(arch, Numero)            # leer una lina el la posicion Numero, comienza en 1
# Clear_Line(arch, Numero)          # Borrar una linea en la posicion Numero
# Update_Line(arch, Numero, Dato)   # actualizar una lineas en la posicion Numero, incluir el/n
# Add_Line_End(arch, Dato)          # agrega una lina al final del archivo, incluir el/n
# Add_Line_Pos(arch, Numero, Dato)  # agrega una lina en al posicion Numero, incluir el/n
# Num_lines(arch)                   # conteo de nuemero de lineas
