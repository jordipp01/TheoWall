import json
import sys

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
    nombre = input("\x1b[0;38m" + "\nNombre: ")
    apellidos = input("\x1b[0;38m" + "Apellidos: ")
    usuario_in = input("\x1b[0;38m" + "Usuario: ")
    email = input("\x1b[0;38m" + "Email: ")
    pwd_in = input("\x1b[0;38m" + "Contraseña: ")
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
        usuario = input("\x1b[0;38m" + "\nUsuario: ")
        pwd = input("\x1b[0;38m" + "Contraseña: ")
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
                print("\x1b[0;34m" + "\nBIENVENIDO, " + data_list[i]["nombre"])
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
                print("\x1b[1;31m" + "\n+ La contraseña no es correcta\n")
                return -2, -2
    if x == False:
        return -1, -1


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
    if cont != [] and str(cont[0])[0:-64] != empty:
        string_cont = str(cont[0])
        decrypt = symmetric_decryption(string_cont[0:-64], usuario_log)
        decrypt_h = hash_msg(str(decrypt), usuario_log)
        if decrypt_h != string_cont[-64:]:
            print("\x1b[1;31m" + "+ La base de datos ha sido dañada")
        else:
            print("\x1b[1;34m" + "\nCredenciales de " + usuario_log.NOMBRE + ":")
            for i in range(0, len(decrypt)):
                print("\x1b[1;34m" + "\n            Id:", "\x1b[0;38m" + str(decrypt[i]["id"]))
                print("\x1b[1;34m" + "    Credencial:", "\x1b[0;38m" + str(decrypt[i]["credencial"]))
            print()
            return 0
    else:
        print("\x1b[1;31m" + "\n+ El usuario no tiene credenciales\n")
        return -1

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
        string_cont = str(cont[0])
        decrypt = symmetric_decryption(string_cont[0:-64], usuario_log)

    decrypt.append(data_create)

    data_encrypted = symmetric_encryption(str(decrypt), usuario_log)
    data_list[usuario_log.NUM_USUARIO]["contenido"] = []
    msg_hash = hash_msg(str(decrypt), usuario_log)
    data_list[usuario_log.NUM_USUARIO]["contenido"].append(data_encrypted + str(msg_hash))
    save(data_list)
    print("\x1b[0;32m" + "\nCredencial creada correctamente\n")

def edit_user_field(usuario_log, nw_value, item):
    """Modifica el campo del perfil del usuario"""
    label = ""
    if item == "1":
        label = "nombre"
    elif item == "2":
        label = "apellidos"
    elif item == "3":
        label = "usuario"
    elif item == "4":
        label = "email"
    elif item == "5":
        label = "password"

    data_list = load()
    data_list[usuario_log.NUM_USUARIO][label] = nw_value
    save(data_list)

def del_credential(usuario_log):
    """Elimina una credencial existente"""
    data_list = load()
    decrypt = []
    id_cred =input("Id de la credencial a eliminar: ")
    cont = data_list[usuario_log.NUM_USUARIO]["contenido"]
    string_cont = str(cont[0])
    decrypt = symmetric_decryption(string_cont[0:-64], usuario_log)

    found = False
    for i in range(0, len(decrypt)):
        if id_cred == decrypt[i]["id"]:
            found = True
            decrypt.pop(i)
            data_encrypted = symmetric_encryption(str(decrypt), usuario_log)
            data_list[usuario_log.NUM_USUARIO]["contenido"] = []
            msg_hash = hash_msg(str(decrypt), usuario_log)
            data_list[usuario_log.NUM_USUARIO]["contenido"].append(data_encrypted + str(msg_hash))
            save(data_list)
            print("\x1b[0;32m" + "\nCredencial eliminada correctamente\n")
            break

    if found == False:
        print("\x1b[1;31m" + "\n+ Id no encontrado\n")




def modificar_usuario(item, usuario_log, user_data):
    """Modifica el perfil de usuario"""
    if item == "1":
        nw_name = input("\x1b[0;38m" + "Nuevo nombre: ")
        user_data["nombre"] = nw_name
        usuario_log.NOMBRE = nw_name
        edit_user_field(usuario_log, nw_name, item)
        return usuario_log, user_data

    elif item == "2":
        nw_ape = input("\x1b[0;38m" + "Nuevos apellidos: ")
        user_data["apellidos"] = nw_ape
        usuario_log.APELLIDOS = nw_ape
        edit_user_field(usuario_log, nw_ape, item)
        return usuario_log, user_data


    elif item == "3":
        nw_us = input("\x1b[0;38m" + "Nuevo usuario: ")
        user_data["usuario"] = nw_us
        usuario_log.USUARIO = nw_us
        edit_user_field(usuario_log, nw_us, item)
        return usuario_log, user_data


    elif item == "4":
        nw_email = input("\x1b[0;38m" + "Nuevo email: ")
        user_data["email"] = nw_email
        usuario_log.EMAIL = nw_email
        edit_user_field(usuario_log, nw_email, item)
        return usuario_log, user_data


    elif item == "5":


        data_list = load()
        cont = data_list[usuario_log.NUM_USUARIO]["contenido"]
        string_cont = str(cont[0])
        decrypt = symmetric_decryption(string_cont[0:-64], usuario_log)
        decrypt_h = hash_msg(str(decrypt), usuario_log)
        if decrypt_h != string_cont[-64:]:
            print("\x1b[1;31m" + "+ La base de datos ha sido dañada")

        nw_pwd = input("\x1b[0;38m" + "Nueva contraseña: ")
        nw_pwd_h = hash_pwd(nw_pwd + usuario_log.SALT)
        user_data["password"] = nw_pwd_h
        usuario_log.PASSWORD = nw_pwd

        pwd_b = nw_pwd.encode('utf-8')
        pwd_hex = pwd_b.hex()
        usuario_log.PADDING = padding(pwd_hex, 64)


        edit_user_field(usuario_log, nw_pwd_h, item)

        data_encrypted = symmetric_encryption(str(decrypt), usuario_log)
        data_list[usuario_log.NUM_USUARIO]["contenido"] = []
        msg_hash = hash_msg(str(decrypt), usuario_log)
        data_list[usuario_log.NUM_USUARIO]["contenido"].append(data_encrypted + str(msg_hash))
        save(data_list)

        return usuario_log, user_data




def modificar_credencial(usuario_log):
    """Modifica una credencial existente"""
    data_list = load()
    id_mod = ""
    decrypt = []
    id_cred = ""
    cont = data_list[usuario_log.NUM_USUARIO]["contenido"]
    empty = symmetric_encryption("[]", usuario_log)
    empty_b = True

    if cont != [] and cont != empty:
        empty_b = False
        id_mod = input("\x1b[0;38m" + "Id de la credencial a modificar: ")

        string_cont = str(cont[0])
        decrypt = symmetric_decryption(string_cont[0:-64], usuario_log)

        if empty_b != True:
            correct = False
            while correct == False:
                found = False
                for i in range(0, len(decrypt)):
                    if id_mod == decrypt[i]["id"]:
                        found = True

                        print("\x1b[0;38m" + "\n  Modificar id ------------",  "\x1b[0;34m" + "[1]",
                                "\x1b[0;38m" + "\n  Modificar credencial ----",  "\x1b[0;34m" + "[2]",
                                "\x1b[0;38m" + "\n  Modificar todo ----------",  "\x1b[0;34m" + "[3]",
                                "\x1b[0;38m" + "\n  Salir -------------------",  "\x1b[0;34m" + "[q]")
                        tipo = input("\x1b[0;38m" + "Elección: ")

                        if tipo == "1":
                            id_cred = input("\x1b[0;38m" + "\nNuevo id: ")
                            decrypt[i]["id"] = id_cred
                            correct = True

                        elif tipo == "2":
                            id_cred = input("\x1b[0;38m" + "\nNueva credencial: ")
                            decrypt[i]["credencial"] = id_cred
                            correct = True

                        elif tipo == "3":
                            id_cred = input("\x1b[0;38m" + "\nNuevo id: ")
                            decrypt[i]["id"] = id_cred
                            id_cred1 = input("\x1b[0;38m" + "Nueva credencial: ")
                            decrypt[i]["credencial"] = id_cred1
                            correct = True

                        elif tipo == "q" or "Q":
                            correct = True
                            print()
                            break

                        else:
                            print("\x1b[1;31m" + "\n+ Opción inválida")

                        if correct == True:
                            data_encrypted = symmetric_encryption(str(decrypt), usuario_log)
                            data_list[usuario_log.NUM_USUARIO]["contenido"] = []
                            msg_hash = hash_msg(str(decrypt), usuario_log)
                            data_list[usuario_log.NUM_USUARIO]["contenido"].append(data_encrypted + str(msg_hash))
                            save(data_list)
                            print("\x1b[0;32m" + "\nCredencial modificada correctamente\n")
                            break

                if found == False:
                    print("\x1b[1;31m" + "\n+ Id no encontrado\n")
    else:
        print("\x1b[1;31m" + "+ El usuario no tiene credenciales")

if __name__ == '__main__':
    try:
        """Loop principal de la aplicación"""
        sys.tracebacklimit = 0
        usuario_log = None
        app = True
        session = False

        while app == True:
            print("\x1b[0;38m" + "Bienvenido a", "\x1b[3;34m" + "Theowall", "\x1b[0;38m" + """\b, tu gestor de contraseñas y documentos
        Si ya eres usuario -----""", "\x1b[0;34m" + "[1]",
        "\x1b[0;38m" + "\n    Para registrarte -------", "\x1b[0;34m" + "[2]",
        "\x1b[0;38m" + "\n    Para salir -------------", "\x1b[0;34m" + "[q]")

            yn = input("\x1b[0;38m" + "Elección: ")

            if yn == "q" or yn == "Q":
                print("\x1b[1;32m" + "\nCerrando la aplicación...\n")

                break

            else:
                if yn == "1":
                    u_usuario = input("\x1b[0;38m" + "\nUsuario: ")
                    u_pwd = input("\x1b[0;38m" + "Contraseña: ")
                    user_data, usuario_log = login(u_usuario, u_pwd)

                    if user_data == -1:
                        print("\x1b[1;31m" + "+ El usuario no existe\n")
                    else:
                        session = True

                elif yn == "2":
                    user_data, usuario_log = signin()
                    session = True

                else:
                    print("\x1b[1;31m" + "\n+ Opción inválida\n")

                while session == True and user_data != -1 and user_data != -2:
                    print("\x1b[0;38m" + """Panel de control (selecciona una opción):
        Para editar una credencial --------""", "\x1b[0;34m" + "[1]",
        "\x1b[0;38m" + "\n    Para crear una nueva credencial ---", "\x1b[0;34m" + "[2]",
        "\x1b[0;38m" + "\n    Para eliminar una credencial ------", "\x1b[0;34m" + "[3]",
        "\x1b[0;38m" + "\n    Para editar perfil de usuario -----", "\x1b[0;34m" + "[4]",
        "\x1b[0;38m" + "\n    Para cerrar sesión ----------------", "\x1b[0;34m" + "[q]",)
                    modo = input("\x1b[0;38m" + "Elección: ")

                    if modo == "1":
                        err = imprimir_credenciales(usuario_log)
                        if err != -1:
                            modificar_credencial(usuario_log)

                    elif modo == "2":
                        id_create = input("\x1b[0;38m" + "Id: ")
                        cred_create = input("\x1b[0;38m" + "Credencial: ")
                        data_create = {"id": id_create, "credencial": cred_create}
                        add_credential(data_create, usuario_log)

                    elif modo == "3":

                        err = imprimir_credenciales(usuario_log)
                        if err != -1:
                            del_credential(usuario_log)

                    elif modo == "4":
                        correct = False
                        while correct != True:
                            list_user = list(user_data.items())
                            pss = "********************************************************************************************"
                            print("\x1b[0;34m" + "\n[1] -- " + str(list_user[0][0]).capitalize() + ":", "\x1b[0;38m"
                                  + list_user[0][1])
                            print("\x1b[0;34m" + "[2] -- " + str(list_user[1][0]).capitalize() + ":", "\x1b[0;38m"
                                  + list_user[1][1])
                            print("\x1b[0;34m" + "[3] -- " + str(list_user[2][0]).capitalize() + ":", "\x1b[0;38m"
                                  + list_user[2][1])
                            print("\x1b[0;34m" + "[4] -- " + str(list_user[5][0]).capitalize() + ":", "\x1b[0;38m"
                                  + list_user[5][1])
                            print(len(usuario_log.PASSWORD))
                            print(pss[0:3])
                            print("\x1b[0;34m" + "[5] -- " + str(list_user[7][0]).capitalize() + ":", "\x1b[0;38m"
                                  + pss[0:len(usuario_log.PASSWORD)])
                            print("\x1b[0;34m" + "[q] -- Salir")

                            item = input("\x1b[0;38m" + "¿Qué quiere cambiar? Elección: ")
                            print()

                            if item == "1" or item == "2" or item == "3" or item == "4":
                                correct = True
                                usuario_log, user_data = modificar_usuario(item, usuario_log, user_data)

                            elif item == "5":
                                correct = True
                                pwd = input("\x1b[0;38m" + "Introduzca la contraseña anterior: ")
                                pwd_s = (pwd + usuario_log.SALT)
                                pwd_h = hash_pwd(pwd_s)
                                if pwd_h != list_user[7][1]:
                                    print("\x1b[1;31m" + "\n+ Contraseña incorrecta\n")
                                    break

                                usuario_log, user_data = modificar_usuario(item, usuario_log, user_data)

                            elif item == "q" or item == "Q":
                                break

                            else:
                                print("\x1b[1;31m" + "+ Opción inválida")


                    elif modo == "q":
                        print("\x1b[1;32m" + "\nCerrando la sesión...\n")
                        sesion = False
                        usuario_log = None
                        break


    except:
        print("\x1b[1;31m" + "\n*******************************")
        print("HA OCURRIDO UN ERROR DE SISTEMA")
        print("*******************************")
        raise SystemError from None


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

