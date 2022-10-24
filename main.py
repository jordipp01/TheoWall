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
    usuario_in = input("Usuario: ")
    email = input("Email: ")
    pwd_in = input("Contraseña: ")
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
    nonce1 = nonce()

    pwd_b = pwd_in.encode('utf-8')
    pwd_hex = pwd_b.hex()
    padding1 = padding(pwd_hex, 64)

    pwd_salt = pwd_in + salt

    pwd_h = hash_pwd(pwd_salt)
    data = {"nombre": nombre, "apellidos": apellidos, "usuario": usuario_in, "salt": salt, "nonce": nonce1,
            "email": email, "padding": padding1, "password": str(pwd_h), "contenido": contenido}
    add_item(data)

    user_data, usuario_log = login(usuario_in, pwd_in)
    while user_data == -1:
        usuario = input("\nUsuario: ")
        pwd = input("Contraseña: ")
        user_data, usuario_log = login(usuario, pwd)
    return user_data, usuario_log


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
                                  "nonce": data_list[i]["nonce"],
                                  "email": data_list[i]["email"],
                                  "padding": data_list[i]["padding"],
                                  "password": u_pwd}
                usuario_log = UserVariables(data_variables)
                return data_list[i], usuario_log
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

def imprimir_credenciales(usuario_log):
    """Imprime todas las credenciales del usuario"""
    data_list = load()
    decrypt = []
    cont = data_list[usuario_log.NUM_USUARIO]["contenido"]
    empty = symmetric_encryption("[]", usuario_log)
    if cont != [] and data_list != empty:
        decrypt = symmetric_decryption(str(cont[0]), usuario_log)
    for i in range(0, len(decrypt)):
        print("\n        Id: " + str(decrypt[i]["id"]))
        print("Credencial: " + str(decrypt[i]["credencial"]))

def save(data_list):
    """Guarda data_list en el archivo JSON"""
    with open("data_file.json", "w", encoding="utf-8", newline="") as file:
        json.dump(data_list, file, indent=2)

def add_item(item):
    """Añade un nuevo item a data_list y actualiza el archivo JSON"""
    data_list = load()
    data_list.append(item)
    save(data_list)

def add_credential(data_create, usuario_log):
    """Añade una nueva credencial"""
    data_list = load()
    decrypt = []
    cont = data_list[usuario_log.NUM_USUARIO]["contenido"]
    empty = symmetric_encryption("[]", usuario_log)

    if cont != [] and data_list != empty:
        decrypt = symmetric_decryption(str(cont[0]), usuario_log)

    decrypt.append(data_create)

    data_encrypted = symmetric_encryption(str(decrypt), usuario_log)
    data_list[usuario_log.NUM_USUARIO]["contenido"] = []
    data_list[usuario_log.NUM_USUARIO]["contenido"].append(data_encrypted)
    save(data_list)

def edit_user_field(usuario_log, nw_value, item):
    """Modifica el campo del perfil del usuario"""
    data_list = load()
    data_list[usuario_log.NUM_USUARIO][item] = nw_value
    save(data_list)

def del_credential(usuario_log):
    """Elimina una credencial existente"""
    data_list = load()
    decrypt = []
    id_cred =""
    cont = data_list[usuario_log.NUM_USUARIO]["contenido"]
    empty = symmetric_encryption("[]", usuario_log)
    empty_b = True
    if cont[0] != [] and cont[0] != empty:
        id_cred = input("\nId: ")
        decrypt = symmetric_decryption(str(cont[0]), usuario_log)
        empty_b = False

    if empty_b != True:
        found = False
        for i in range(0, len(decrypt)):
            if id_cred == decrypt[i]["id"]:
                found = True
                decrypt.pop(i)
                data_encrypted = symmetric_encryption(str(decrypt), usuario_log)
                data_list[usuario_log.NUM_USUARIO]["contenido"] = []
                data_list[usuario_log.NUM_USUARIO]["contenido"].append(data_encrypted)
                save(data_list)
                break

        if found == False:
            print("Id no encontrado")
    else:
        print("El usuario no tiene credenciales")




def modificar_usuario(item, usuario_log):
    """Modifica el perfil de usuario"""
    if item == "nombre":
        nw_name = input("Nuevo nombre: ")
        edit_user_field(usuario_log.NUM_USUARIO, nw_name, item)

    elif item == "apellidos":
        nw_ape = input("Nuevos apellidos: ")
        edit_user_field(usuario_log.NUM_USUARIO, nw_ape, item)

    elif item == "usuario":
        nw_us = input("Nuevo usuario: ")
        edit_user_field(usuario_log.NUM_USUARIO, nw_us, item)

    elif item == "email":
        nw_email = input("Nuevo email: ")
        edit_user_field(usuario_log.NUM_USUARIO, nw_email, item)

    elif item == "password":
        nw_pwd = input("Nueva contraseña: ")
        nw_pdw_h = hash_pwd(nw_pwd + usuario_log.SALT)
        edit_user_field(usuario_log.NUM_USUARIO, nw_pdw_h, item)



def modificar_credencial(usuario_log):
    """Modifica una credencial existente"""
    data_list = load()
    id_mod = ""
    decrypt = []
    id_cred = ""
    cont = data_list[usuario_log.NUM_USUARIO]["contenido"]
    empty = symmetric_encryption("[]", usuario_log)
    empty_b = True

    if cont[0] != [] and cont[0] != empty:
        empty_b = False
        id_mod = input("Id de la credencial a modificar: ")


    decrypt = symmetric_decryption(str(cont[0]), usuario_log)
    if empty_b != True:
        found = False
        for i in range(0, len(decrypt)):
            if id_mod == decrypt[i]["id"]:
                found = True

                tipo = input("\n  Modificar id [1]"
                             "\n  Modificar credencial [2]"
                             "\n  Modificar todo [3]\n")

                if tipo == "1":
                    id_cred = input("\nNuevo id: ")
                    decrypt[i]["id"] = id_cred

                elif tipo == "2":
                    id_cred = input("\nNueva credencial: ")
                    decrypt[i]["credencial"] = id_cred

                elif tipo == "3":
                    id_cred = input("\nNuevo id: ")
                    decrypt[i]["id"] = id_cred
                    id_cred1 = input("\nNueva credencial: ")
                    decrypt[i]["credencial"] = id_cred1

                data_encrypted = symmetric_encryption(str(decrypt), usuario_log)
                data_list[usuario_log.NUM_USUARIO]["contenido"] = []
                data_list[usuario_log.NUM_USUARIO]["contenido"].append(data_encrypted)
                save(data_list)
                break

        if found == False:
            print("Id no encontrado")
    else:
        print("El usuario no tiene credenciales")

if __name__ == '__main__':
    """Loop principal de la aplicación"""
    usuario_log = None
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
                user_data, usuario_log = login(u_usuario, u_pwd)
                while user_data == -1:
                    u_usuario = input("\nUsuario: ")
                    u_pwd = input("Contraseña: ")
                    user_data, usuario_log = login(u_usuario, u_pwd)
                del u_usuario, u_pwd
            elif yn == "n" or yn == "N":
                x = True
                user_data, usuario_log = signin()
            elif yn == "q" or yn == "Q":
                app = False
                x = True
            else:
                print("Input incorrecto\n")
                print("Si ya eres usuario, teclea [Y]")
                print("Para registrarte, teclea [N]")
                yn = input()

        imprimir_credenciales(usuario_log)

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
                    imprimir_credenciales(usuario_log)
                    modificar_credencial(usuario_log)
                elif modo == "2":
                    id_create = input("Id: ")
                    cred_create = input("Credencial: ")
                    data_create = {"id": id_create, "credencial": cred_create}
                    add_credential(data_create, usuario_log)
                elif modo == "3":
                    imprimir_credenciales(usuario_log)
                    del_credential(usuario_log)
                elif modo == "4":
                    list_user = list(user_data.items())
                    for i in range(5):
                        print("\n" + list_user[i][0] + ": " + list_user[i][1])
                    item = input("¿Qué quiere cambiar?: ")
                    if item == "password":
                        pwd = input("Introduzca la contraseña anterior: ")
                        pwd_s = (pwd + usuario_log.SALT)
                        pwd_h = hash_pwd(pwd_s)
                        if pwd_h != list_user[5][1]:
                            print("Contraseña incorrecta")

                    modificar_usuario(item, usuario_log)
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

