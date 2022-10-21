import json

from user_variables import UserVariables
from cryptographic_algorithms import *

"""
from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_cors import CORS
"""
"""
import smtplib
"""

"""
app = Flask(__name__)
CORS(app)
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


def signin():
    """Crea un nuevo usuario de la app"""
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
    salt = nonce()

    pwd_salt = pwd + salt

    pwd_h = hash_pwd(pwd_salt)
    data = {"nombre": nombre, "apellidos": apellidos, "usuario": usuario, "salt": salt, "email": email, "password": str(pwd_h),
            "contenido": contenido}
    add_item(data)

    user_data, usuario = login(usuario, pwd)
    while user_data == -1:
        usuario = input("\nUsuario: ")
        pwd = input("Contraseña: ")
        user_data, usuario = login(usuario, pwd)
    return user_data, usuario


def login(u_usuario, u_pwd):
    """Logearse. Pide usuario y contraseña y comprueba en el archivo JSON: usuario + hash_de_contraseña"""
    data_list = load()
    x = False
    for i in range(0,len(data_list)):
        if u_usuario == data_list[i]["usuario"]:
            x = True
            u_pwd_s = u_pwd + data_list[i]["salt"]
            u_pwd_h = hash_pwd(u_pwd_s)
            if u_pwd_h == data_list[i]["password"]:
                print("\nBienvenido " + data_list[i]["nombre"])
                data_variables = {"nombre": data_list[i]["nombre"],
                                  "apellidos": data_list[i]["apellidos"],
                                  "usuario": data_list[i]["usuario"],
                                  "num_usuario": i,
                                  "salt": data_list[i]["salt"],
                                  "email": data_list[i]["email"],
                                  "password": u_pwd}
                usuario = UserVariables(data_variables)
                return data_list[i], usuario
            else:
                print("La contraseña no es correcta")
                return -1, -1
    if x == False:
        print("El usuario no existe")


""
def load():
    """Cargar el JSON en data_list y devuelve data_list"""
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
    """Imprime todas las credenciales del usuario"""
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

def add_credential(data_create, num_usuario):
    """Añade una nueva credencial"""
    data_list = load()

    pwd = symetric_decryption(usuario.PASSWORD)
    key = padding()
    data_create_encrypt = symetric_encryption(str(data_create), key, iv)
    data_list[num_usuario]["contenido"].append(data_create_encrypt)

    data_list[num_usuario]["contenido"].append(data_create)
    save(data_list)

def edit_user_field(num_usuario, nw_value, item):
    """Modifica el campo del perfil del usuario"""
    data_list = load()
    data_list[num_usuario][item] = nw_value
    save(data_list)

def del_credential(num_usuario, id_cred):
    """Elimina una credencial existente"""
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
    """Modifica el perfil de usuario"""
    if item == "nombre":
        nw_name = input("Nuevo nombre: ")
        edit_user_field(num_usuario, nw_name, item)

    elif item == "apellidos":
        nw_ape = input("Nuevos apellidos: ")
        edit_user_field(num_usuario, nw_ape, item)

    elif item == "usuario":
        nw_us = input("Nuevo usuario: ")
        edit_user_field(num_usuario, nw_us, item)

    elif item == "email":
        nw_email = input("Nuevo email: ")
        edit_user_field(num_usuario, nw_email, item)

    elif item == "password":
        nw_pwd = input("Nueva contraseña: ")
        nw_pdw_h = hash_pwd(nw_pwd + usuario.SALT)
        edit_user_field(num_usuario, nw_pdw_h, item)



def modificar_credencial(num_usuario, id_mod):
    """Modifica una credencial existente"""
    data_list = load()
    credenciales = data_list[num_usuario]["contenido"]
    found = False
    print(credenciales)
    for i in range(len(credenciales)):
        if credenciales[i]["id"] == id_mod:
            tipo = input("\n  Modificar id [1]"
                          "\n  Modificar credencial [2]"
                          "\n  Modificar todo [3]\n")
            if tipo == "1":
                nw_value =input("Nuevo id: ")
                data_list[num_usuario]["contenido"][i]["id"] = nw_value
            elif tipo == "2":
                nw_value = input("Nueva credencial: ")
                data_list[num_usuario]["contenido"][i]["credencial"] = nw_value
            elif tipo == "3":
                nw_value1 = input("New id: ")
                data_list[num_usuario]["contenido"][i]["id"] = nw_value1
                nw_value2 = input("Nueva credencial: ")
                data_list[num_usuario]["contenido"][i]["credencial"] = nw_value2
            found = True
    if found == False:
        print("No existe")
    save(data_list)

if __name__ == '__main__':
    """Loop principal de la aplicación"""
    app = True
    while app == True:
        print("""Bienvenido a Theowall, tu gestor de contraseñas y documentos
        
    Si ya eres usuario ----- [y]
    Para registrarte ------- [n]
    Para salir ------------- [q]""")

        yn = input()
        x = False
        while x != True:
            if yn == "y" or yn == "Y":
                x = True
                u_usuario = input("\nUsuario: ")
                u_pwd = input("Contraseña: ")
                user_data, usuario = login(u_usuario, u_pwd)
                while user_data == -1:
                    u_usuario = input("\nUsuario: ")
                    u_pwd = input("Contraseña: ")
                    user_data, usuario = login(u_usuario, u_pwd)
                del u_usuario, u_pwd
            elif yn == "n" or yn == "N":
                x = True
                signin()
            elif yn == "q" or yn == "Q":
                app = False
                x = True
            else:
                print("Input incorrecto\n")
                print("Si ya eres usuario, teclea [Y]")
                print("Para registrarte, teclea [N]")
                yn = input()
        #imprimir_credenciales(user_data)
        if app == True:
            sesion = True
            while sesion == True:
                print("""\nPanel de control (selecciona una opción):  
                Para editar una credencial -------- [1]
                Para crear una nueva credencial --- [2]
                Para eliminar una credencial ------ [3]
                Para editar perfil de usuario ----- [4]
                Para cerrar sesión ---------------- [q]""")
                modo = input("Elección: ")
                modo = modo

                if modo == "1":
                    list_user = user_data["contenido"]
                    for i in range(len(list_user)):
                        print("\n        Id: " + list_user[i]["id"])
                        print("Credencial: " + list_user[i]["credencial"])
                    id_mod = input("Id de la credencial a modificar: ")

                    modificar_credencial(usuario.NUM_USUARIO, id_mod)
                elif modo == "2":
                    id_create = input("Id: ")
                    cred_create = input("Credencial: ")
                    data_create = {"id": id_create, "credencial": cred_create}
                    add_credential(data_create, usuario.NUM_USUARIO)
                elif modo == "3":
                    id_delete = input("Id: ")
                    del_credential(usuario.NUM_USUARIO, id_delete)
                elif modo == "4":
                    list_user = list(user_data.items())
                    for i in range(5):
                        print("\n" + list_user[i][0] + ": " + list_user[i][1])
                    item = input("¿Qué quiere cambiar?: ")
                    if item == "password":
                        pwd = input("Introduzca la contraseña anterior: ")
                        pwd_s = (pwd + usuario.SALT)
                        pwd_h = hash_pwd(pwd_s)
                        if pwd_h != list_user[5][1]:
                            print("Contraseña incorrecta")

                    modificar_usuario(item, usuario.NUM_USUARIO)
                elif modo == "q":
                    sesion = False

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

