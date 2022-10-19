import json
import hashlib

"""
from flask import Flask, render_template, redirect, url_for, request, jsonify
"""

"""
import smtplib
import random
import string
"""

"""
app = Flask(__name__)
"""



"""
def correo_verificacion(email, cod):
    "Función: Envía un correo a la dirección de correo (email) del nuevo usuario con un código de verificación (cod)"
    mensaje = 'El código de verificación es: ' + str(cod)
    asunto = 'Código verificación'

    mensaje = 'Subject: {}\n\n{}'.format(asunto.encode('latin-1'), mensaje.encode('latin-1'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    
    server.login('noreply.theowall@gmail.com', 'xeibjnzturewbsuv')

    server.sendmail('noreply.theowall@gmail.com', str(email), mensaje)

    server.quit()

    print("Correo enviado")
"""



"""
def gen_codigo(len=6):
    "Función: genera un código aaleatorio de 6 dígitos --> Letras_en_mayúscula + números"
    code_str = string.ascii_uppercase + string.digits
    return ''.join(random.sample(code_str,len))
"""

def hash_pwd(pwd):
    pwd_b = bytes(pwd, 'utf-8')
    hash = hashlib.sha256()
    hash.update(pwd_b)
    pwd_h = hash.hexdigest()
    return pwd_h


def signin():
    """Función: Crea un nuevo usuario de la app, genera hash de la contraseña e introduce sus datos en el archivo JSON"""
    nombre = input("Nombre: ")
    apellidos = input("Apellidos: ")
    usuario = input("Usuario: ")
    email = input("Email: ")
    pwd = input("Contraseña: ")
    contenido = []

    """
    cod = gen_codigo()
    correo_verificacion(email, cod)
    cod_ok = False
    print("Le acabamos de enviar un correo a la dirección " + email + " con un código de verificación")
    code = input("Código de verificación: ")
    if code == cod:
        cod_ok = True
    else:
        print("El código no es correcto")
    """

    pwd_h = hash_pwd(pwd)
    data = {"nombre": nombre, "apellidos": apellidos, "usuario": usuario, "email": email, "password": str(pwd_h),
            "contenido": contenido}
    add_item(data)


def login():
    """Función: Logearse. Pide usuario y contraseña y comprueba en el archivo JSON: usuario + hash_de_contraseña"""
    u_usuario = input("Usuario: ")
    pwd = input("Contraseña: ")
    u_pwd_h = hash_pwd(pwd)

    data_list = load()
    x = False
    for i in range(0,len(data_list)):
        if u_usuario == data_list[i]["usuario"]:
            x = True
            if u_pwd_h == data_list[i]["password"]:
                print("Bienvenido " + data_list[i]["usuario"])
                return data_list[i], i
            else:
                print("La contraseña no es correcta")
    if x == False:
        print("El usuario no existe")


""
def load():
    """Carga los datos en data_list/data"""
    try:
        with open("data_file.json", "r", encoding="utf-8", newline="") as file:
            data_list = json.load(file)
            return data_list
    except:
        f = open("data_file.json", "w")
        data = []
        save(data)
        return data

def imprimir_credenciales(user_data):
    for i in range(len(user_data["contenido"])):
        print("id: " + user_data["contenido"][i]["id"])
        print("credencial: " + user_data["contenido"][i]["credencial"])
        print("")

def save(data_list):
    """Guarda data_list en el archivo JSON"""
    with open("data_file.json", "w", encoding="utf-8", newline="") as file:
        json.dump(data_list, file, indent=2)

def add_item(item):
    """Añade un nuevo item a data_list y actualiza el archivo JSON"""
    data_list = load()
    data_list.append(item)
    save(data_list)

def add_credential(cred, num_usuario):
    data_list = load()
    data_list[num_usuario]["contenido"].append(cred)
    save(data_list)

def add_user(num_usuario, nw_value, item):
    data_list = load()
    data_list[num_usuario][item] = nw_value
    save(data_list)

def del_credential(num_usuario, id_cred):
    data_list = load()
    x = False
    for i in range(0, len(data_list[num_usuario])):
        if id_cred == data_list[num_usuario]["contenido"][i]["id"]:
            x = True
            data_list[num_usuario]["contenido"].pop(i)
            save(data_list)
            break
    if x == False:
        print("El id no existe")

def modificar_usuario(item, num_usuario):
    if item == "nombre":
        nw_name = input("Nuevo nombre: ")
        add_user(num_usuario, nw_name, item)

    elif item == "apellidos":
        nw_ape = input("Nuevos apellidos: ")
        add_user(num_usuario, nw_ape, item)

    elif item == "usuario":
        nw_us = input("Nuevo usuario: ")
        add_user(num_usuario, nw_us, item)

    elif item == "email":
        nw_email = input("Nuevo email: ")
        add_user(num_usuario, nw_email, item)

    elif item == "password":
        nw_pwd = input("Nueva contraseña: ")
        nw_pdw_h = hash_pwd(nw_pwd)
        add_user(num_usuario, nw_pdw_h, item)



def modificar_credencial(id_mod):
    pass


print("Bienvenido a Theowall, tu gestor de contraseñas y documentos\n")
print("Si ya eres usuario, teclea [Y]")
print("para registrarte, teclea [N]")
yn = input()
x = False
while x != True:
    if yn == "y" or yn == "Y":
        x = True
        user_data, num_usuario = login()
    elif yn == "n" or yn == "N":
        x = True
        signin()
    else:
        print("Input incorrecto\n")
        print("Si ya eres usuario, teclea [Y]")
        print("Para registrarte, teclea [N]")
        yn = input()
imprimir_credenciales(user_data)

print("""Panel de control (selecciona una opción):  
    Para editar una credencial -------- [1]
    Para crear una nueva credencial --- [2]
    Para eliminar una credencial ------ [3]
    Para editar perfil de usuario ----- [4]""")
modo = input("Elección: ")
modo = int(modo)

if modo == 1:
    id_mod = input("Id de la credencial a modificar: ")
    modificar_credencial(id_mod)
elif modo == 2:
    id_create = input("Id: ")
    cred_create = input("Credencial: ")
    data_create = {"id": id_create, "credencial": cred_create}
    add_credential(data_create, num_usuario)
elif modo == 3:
    id_delete = input("Id: ")
    del_credential(num_usuario, id_delete)
elif modo == 4:
    list_user = list(user_data.items())
    for i in range(5):
        print("\n" + list_user[i][0] + ": " + list_user[i][1])
    item = input("¿Qué quiere cambiar?: ")
    if item == "password":
        pwd = input("Introduzca la contraseña anterior: ")
        pwd_h = hash_pwd(pwd)

        if pwd_h != list_user[4][1]:
            print("Contraseña incorrecta")

    modificar_usuario(item, num_usuario)

else:
    print("No existe")







"""
@app.route('/data_file', methods = ['GET'])
def get_data_file():
    if request.method == 'GET':
        # Mensaje impreso en la terminal de python
        print("---------------- He recibido --------------------")
        print("data_file")
        print("-------------------------------------------------")
        data_file = load()
        return jsonify(data_file), 200


app.run(host="0.0.0.0", port="5000")
"""

