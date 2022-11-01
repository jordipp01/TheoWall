"""Loop principal de la aplicación"""

import json
import sys
import smtplib

from user_variables import UserVariables
from cryptographic_algorithms import *
from exceptions import Exceptions
from validaciones.nombre_validacion import Nombre
from validaciones.apellidos_validacion import Apellidos
from validaciones.usuario_validacion import Usuario
from validaciones.email_validacion import Email
from validaciones.password_validacion import Password


def correo_verificacion(email, cod):
    """Función: Envía un correo a la dirección de correo (email) del nuevo usuario con un código de
    verificación (cod)"""
    mensaje = 'El codigo de verificacion es: ' + str(cod)
    asunto = 'Codigo verificacion'

    mensaje = 'Subject: {}\n\n{}'.format(asunto.encode('latin-1'), mensaje.encode('latin-1'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()

    server.login('noreply.theowall@gmail.com', 'xeibjnzturewbsuv')

    server.sendmail('noreply.theowall@gmail.com', str(email), mensaje)

    server.quit()

    print("Correo enviado")


def gen_codigo(length=6):
    """Función: genera un código aaleatorio de 6 dígitos --> Letras_en_mayúscula + números"""
    code_str = string.ascii_uppercase + string.digits
    return ''.join(random.sample(code_str, length))


def signin():
    """Crea un nuevo usuario de la app"""
    # Se recibe el nombre del usuario y se valida
    nombre = input("\x1b[0;38m" + "\nNombre: ")
    nombre = Nombre(nombre).value
    if nombre == -1:
        return 0, 0

    # Se reciben los apellidos del usuario y se validan
    apellidos = input("\x1b[0;38m" + "Apellidos: ")
    apellidos = Apellidos(apellidos).value
    if apellidos == -1:
        return 0, 0

    # Se recibe el nombre de usuario y se valida
    usuario_in = input("\x1b[0;38m" + "Usuario: ")
    usuario_in = Usuario(usuario_in).value
    if usuario_in == -1:
        return 0, 0

    # Se recibe el email y se valida
    email = input("\x1b[0;38m" + "Email: ")
    email = Email(email).value
    if email == -1:
        return 0, 0

    # Se recibe la contraseña y se valida
    pwd_in = input("\x1b[0;38m" + "Contraseña: ")
    pwd_in = Password(pwd_in).value
    if pwd_in == -1:
        return 0, 0
    contenido = []

    data_list = load()
    for i in range(len(data_list)):
        # Comprobar que el nombre de usuario no existe en la base de datos
        if data_list[i]["usuario"] == usuario_in:
            return -3, -3

        # Comprobar que el email no existe en la base de datos
        elif data_list[i]["email"] == email:
            return -4, -4

    # Se genera un código de verificación u se envía un correo a la dirección introducida por el usuario
    # cod = gen_codigo()
    # correo_verificacion(email, cod)
    # cod_ok = False
    # print("Le acabamos de enviar un correo a la dirección " + email + " con un código de verificación")
    # code = input("Código de verificación: ")
    # if code == cod:
    #     cod_ok = True
    # else:
    #     print("El código no es correcto")

    # Se generan el salt y el nonce personales del usuario
    salt = nonce()
    nonce1 = nonce()

    # Se genera el padding de la contraseña maestra y se hace el hash de la contraseña maestra
    pwd_b = pwd_in.encode('utf-8')
    pwd_hex = pwd_b.hex()
    padding1 = padding(pwd_hex, 64)
    pwd_salt = pwd_in + salt
    pwd_h = hash_pwd(pwd_salt)

    data = {"nombre": nombre, "apellidos": apellidos, "usuario": usuario_in, "salt": salt, "nonce": nonce1,
            "email": email, "padding": padding1, "password": str(pwd_h), "contenido": contenido}

    # Se añaden los datos del nuevo usuario en la base de datos
    add_item(data)

    # Login automático después de registrarse
    user_data, usuario_log = login(usuario_in, pwd_in)

    return user_data, usuario_log


def login(u_usuario, u_pwd):
    """Logearse. Pide usuario y contraseña y comprueba en el archivo JSON: usuario + hash_de_contraseña"""
    data_list = load()
    x = False

    for i in range(0, len(data_list)):
        # Se compara el usuario escrito con la lista de usuarios en la base de datos
        if u_usuario == data_list[i]["usuario"]:
            u_pwd_s = u_pwd + data_list[i]["salt"]
            u_pwd_h = hash_pwd(u_pwd_s)
            # Se compara el hash de la contraseña maestra escrita con el hash guardado en la base de datos
            if u_pwd_h == data_list[i]["password"]:
                print("\x1b[0;34m" + "\nBIENVENIDO, " + data_list[i]["nombre"])

                # Se crea un diccionario con la información del usuario guardada en la base de datos
                data_variables = {"nombre": data_list[i]["nombre"],
                                  "apellidos": data_list[i]["apellidos"],
                                  "usuario": data_list[i]["usuario"],
                                  "num_usuario": i,
                                  "salt": data_list[i]["salt"],
                                  "nonce": data_list[i]["nonce"],
                                  "email": data_list[i]["email"],
                                  "padding": data_list[i]["padding"],
                                  "password": u_pwd}

                # Se crea una instancia de UserVariables para tener a mano los datos del usuario logueado
                usuario_log = UserVariables(data_variables)
                return data_list[i], usuario_log

            # La contraseña escrita no coincide con la de registro
            else:
                print("\x1b[1;31m" + "\n+ ERROR -->", "\x1b[1;35m" + "La contraseña no es correcta\n")
                return -2, -2

    # El usuario escrito no existe en la base de datos
    if not x:
        return -1, -1


def load():
    """Cargar el JSON en data_list y devuelve data_list"""
    try:
        # Se abre el archivo data_file.json si existe
        with open("data_file.json", "r", encoding="utf-8", newline="") as file:
            data_list = json.load(file)
            return data_list
    except:
        # Se crea y se abre el archivo data_file.json
        open("data_file.json", "w")
        data = []
        save(data)
        return data


def imprimir_credenciales(usuario_log):
    """Imprime todas las credenciales del usuario"""
    data_list = load()
    cont = data_list[usuario_log.NUM_USUARIO]["contenido"]
    empty = symmetric_encryption("[]", usuario_log)

    # Se comprueba si el usuario tiene credenciales guardadas
    if cont != [] and str(cont[0])[0:-64] != empty:
        string_cont = str(cont[0])
        # Se comprueba integridad del contenido cifrado del usuario
        try:
            decrypt = symmetric_decryption(string_cont[0:-64], usuario_log)
            decrypt_h = hash_msg(str(decrypt), usuario_log)

            # Si la base de datos ha sido dañada pero se puede descifrar, se imprime mensaje en pantalla
            if decrypt_h != string_cont[-64:]:
                print("\x1b[1;31m" + "\n+ ERROR -->", "\x1b[1;35m" + "La base de datos ha sido dañada\n")

        # Si la base de datos ha sido dañada y salta SyntaxError, se imprime mensaje en pantalla
        except:
            print("\x1b[1;31m" + "\n+ ERROR -->", "\x1b[1;35m" + "La base de datos ha sido dañada\n")
            return -1

        else:
            # Se imprimen las credenciales del usuario
            print("\x1b[1;34m" + "\nCredenciales de " + usuario_log.NOMBRE + ":")
            for i in range(0, len(decrypt)):
                print("\x1b[1;34m" + "\n            Id:", "\x1b[0;38m" + str(decrypt[i]["id"]))
                print("\x1b[1;34m" + "    Credencial:", "\x1b[0;38m" + str(decrypt[i]["credencial"]))
            print()
            return 0

    else:

        # El usuario no tiene credenciales guardadas
        print("\x1b[1;31m" + "\n+ ERROR -->", "\x1b[1;35m" + "El usuario no tiene credenciales\n")
        return -1


def seq_encryptacion(data_list, decrypt, usuario_log):
    """Sequencia de cifrado de credenciales del usuario"""
    # Se cifra la información de las credenciales
    data_encrypted = symmetric_encryption(str(decrypt), usuario_log)
    data_list[usuario_log.NUM_USUARIO]["contenido"] = []

    # Se hace el hash de la información de las credenciales
    msg_hash = hash_msg(str(decrypt), usuario_log)

    # Se concatena el contenido cifrado con el hash del contenido --> HMAC; y se guarda en la base de datos
    data_list[usuario_log.NUM_USUARIO]["contenido"].append(data_encrypted + str(msg_hash))
    save(data_list)


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

    # Comprueba si el usuario tiene credenciales en la base de datos
    if cont != [] and data_list != empty:
        string_cont = str(cont[0])

        # Se comprueba integridad del contenido cifrado del usuario
        try:
            decrypt = symmetric_decryption(string_cont[0:-64], usuario_log)
            decrypt_h = hash_msg(str(decrypt), usuario_log)

            # Si la base de datos ha sido dañada pero se puede descifrar, se imprime mensaje en pantalla
            if decrypt_h != string_cont[-64:]:
                print("\x1b[1;31m" + "\n+ ERROR -->", "\x1b[1;35m" + "La base de datos ha sido dañada\n")

        # Si la base de datos ha sido dañada y salta SyntaxError, se imprime mensaje en pantalla
        except SyntaxError or UnicodeDecodeError:
            print("\x1b[1;31m" + "\n+ ERROR -->", "\x1b[1;35m" + "La base de datos ha sido dañada\n")
            return -1

    # Se le añade la credencial nueva a la lista que contiene las credenciales del usuario
    decrypt.append(data_create)

    # Se encripta la lista con las credenciales anteriores más la nueva credencial y se guarda en la base de datos
    seq_encryptacion(data_list, decrypt, usuario_log)

    # Mensaje de credencial creada correctamente
    print("\x1b[0;32m" + "\n+ Credencial creada correctamente\n")


def edit_user_field(usuario_log, nw_value, item, data_list, pad=""):
    """Modifica el campo del perfil del usuario"""
    label = ""
    label2 = "padding"

    # Comprobar elección del usuario
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

    # Modificación del perfil y guardado de los nuevos valores en la base de datos
    data_list[usuario_log.NUM_USUARIO][label] = nw_value
    if item == "5":
        data_list[usuario_log.NUM_USUARIO][label2] = pad
    save(data_list)

    return data_list


def del_credential(usuario_log):
    """Elimina una credencial existente"""
    data_list = load()
    id_cred = input("Id de la credencial a eliminar: ")
    cont = data_list[usuario_log.NUM_USUARIO]["contenido"]
    string_cont = str(cont[0])

    # Se descifra el contenido de las credenciales del usuario
    decrypt = symmetric_decryption(string_cont[0:-64], usuario_log)

    found = False
    for i in range(0, len(decrypt)):
        # Por cada credencial, se comprueba si el id es igual al escrito por el usuario
        if id_cred == decrypt[i]["id"]:
            found = True

            # Se elimina la credencial de la lista
            decrypt.pop(i)

            # Se cifra de nuevo el contenido de las credenciales y se guarda
            seq_encryptacion(data_list, decrypt, usuario_log)

            # Se imprime mensaje de credencial eliminada correctamente
            print("\x1b[0;32m" + "\n+ Credencial eliminada correctamente\n")
            break

    # Si el id de la credencial que el usuario ha escrito no existe, se imprime mensaje
    if not found:
        print("\x1b[1;31m" + "\n+ ERROR -->", "\x1b[1;35m" + "Id no encontrado\n")


def modificar_usuario(item, usuario_log, user_data):
    """Modifica el perfil de usuario"""
    data_list = load()

    # Se comprueba la elección del usuario

    # El usuario quiere modificar el nombre
    if item == "1":
        nw_name = input("\x1b[0;38m" + "Nuevo nombre: ")

        # Validación del nuevo nombre
        nw_name = Nombre(nw_name).value
        if nw_name == -1:
            return usuario_log, user_data

        # Se actualiza el nuevo nombre en al base de datos y en la memoria de sesión
        user_data["nombre"] = nw_name
        usuario_log.NOMBRE = nw_name
        edit_user_field(usuario_log, nw_name, item, data_list)

        # Mensaje de operación realizada correctamente
        print("\x1b[0;32m" + "\n+ Nombre modificado correctamente\n")
        return usuario_log, user_data


    # El usuario quiere modificar los apelliddos
    elif item == "2":
        nw_ape = input("\x1b[0;38m" + "Nuevos apellidos: ")

        # Validación de los nuevos appelidos
        nw_ape = Apellidos(nw_ape).value
        if nw_ape == -1:
            return usuario_log, user_data

        # Se actualiza los nuevs apellidos en al base de datos y en la memoria de sesión
        user_data["apellidos"] = nw_ape
        usuario_log.APELLIDOS = nw_ape
        edit_user_field(usuario_log, nw_ape, item, data_list)

        # Mensaje de operación realizada correctamente
        print("\x1b[0;32m" + "\n+ Apellidos modificados correctamente\n")
        return usuario_log, user_data

    # El usuario quiere modificar el nombre de usuario
    elif item == "3":
        nw_us = input("\x1b[0;38m" + "Nuevo usuario: ")

        # Validación del nuevo nombre de usuario
        nw_us = Usuario(nw_us).value
        if nw_us == -1:
            return usuario_log, user_data

        # Se actualiza el nuevo nombre de usuario en al base de datos y en la memoria de sesión
        user_data["usuario"] = nw_us
        usuario_log.USUARIO = nw_us
        edit_user_field(usuario_log, nw_us, item, data_list)

        # Mensaje de operación realizada correctamente
        print("\x1b[0;32m" + "\n+ Nombre de usuario modificado correctamente\n")
        return usuario_log, user_data

    # El usuario quiere modificar el email
    elif item == "4":
        nw_email = input("\x1b[0;38m" + "Nuevo email: ")

        # Validación del nuevo email
        nw_email = Email(nw_email).value
        if nw_email == -1:
            return usuario_log, user_data

        # Se actualiza el nuevo email en al base de datos y en la memoria de sesión
        user_data["email"] = nw_email
        usuario_log.EMAIL = nw_email
        edit_user_field(usuario_log, nw_email, item, data_list)

        # Mensaje de operación realizada correctamente
        print("\x1b[0;32m" + "\n+ Email modificado correctamente\n")
        return usuario_log, user_data

    # El usuario quiere modificar la contraseña maestra
    elif item == "5":
        decrypt = []
        cont = data_list[usuario_log.NUM_USUARIO]["contenido"]
        empty = symmetric_encryption("[]", usuario_log)

        # Comprueba si el usuario tiene credenciales en la base de datos
        if cont != [] and data_list != empty:
            string_cont = str(cont[0])

            # Se comprueba integridad del contenido cifrado del usuario
            try:
                decrypt = symmetric_decryption(string_cont[0:-64], usuario_log) # Se descifra el contenido
                decrypt_h = hash_msg(str(decrypt), usuario_log)

                # Si la base de datos ha sido dañada pero se puede descifrar, se imprime mensaje en pantalla
                if decrypt_h != string_cont[-64:]:
                    print("\x1b[1;31m" + "\n+ ERROR -->", "\x1b[1;35m" + "La base de datos ha sido dañada\n")

            # Si la base de datos ha sido dañada y salta SyntaxError, se imprime mensaje en pantalla
            except SyntaxError or UnicodeDecodeError:
                print("\x1b[1;31m" + "\n+ ERROR -->", "\x1b[1;35m" + "La base de datos ha sido dañada\n")
                return usuario_log, user_data

        nw_pwd = input("\x1b[0;38m" + "Nueva contraseña: ")

        # Validación de la nueva contraseña maestra
        nw_pwd = Password(nw_pwd).value
        if nw_pwd == -1:
            return usuario_log, user_data

        # Se actualiza la nueva contraseña maestra en al base de datos y en la memoria de sesión
        nw_pwd_h = hash_pwd(nw_pwd + usuario_log.SALT)
        user_data["password"] = nw_pwd_h
        usuario_log.PASSWORD = nw_pwd

        pwd_b = nw_pwd.encode('utf-8')
        pwd_hex = pwd_b.hex()

        pad = padding(pwd_hex, 64)  # Nuevo padding para la nueva contraseña maestra
        usuario_log.PADDING = pad

        data_list = edit_user_field(usuario_log, nw_pwd_h, item, data_list, pad)

        # Se cifran los datos de contenido con la nueva contraseña maestra + el nuevo padding
        seq_encryptacion(data_list, decrypt, usuario_log)

        # Mensaje de operación realizada correctamente
        print("\x1b[0;32m" + "\n+ Contraseña modificada correctamente\n")
        return usuario_log, user_data


def modificar_credencial(usuario_log):
    """Modifica una credencial existente"""
    data_list = load()
    cont = data_list[usuario_log.NUM_USUARIO]["contenido"]
    empty = symmetric_encryption("[]", usuario_log)

    # Se comprueba si el usuario tiene credenciales guardadas en la base de datos

    if cont != [] and cont != empty:  # Si el usuario tiene credenciales guardadas en la base de datos

        id_mod = input("\x1b[0;38m" + "Id de la credencial a modificar: ")

        string_cont = str(cont[0])
        decrypt = symmetric_decryption(string_cont[0:-64], usuario_log)  # Se descifra el contenido
        correct = False

        # Bucle de opciones dde modificación de credencial
        while not correct:
            found = False
            for i in range(0, len(decrypt)):
                if id_mod == decrypt[i]["id"]: # Si el id de la credencial a modificar existe en la base de datos
                    found = True

                    print("\x1b[0;38m" + "\n  Modificar id ------------", "\x1b[0;34m" + "[1]",
                          "\x1b[0;38m" + "\n  Modificar credencial ----", "\x1b[0;34m" + "[2]",
                          "\x1b[0;38m" + "\n  Modificar todo ----------", "\x1b[0;34m" + "[3]",
                          "\x1b[0;38m" + "\n  Salir -------------------", "\x1b[0;34m" + "[q]")
                    tipo = input("\x1b[0;38m" + "Elección: ")

                    # Comprobar elección del usuario

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

                    elif tipo == "q" or "Q":  # Salir del bucle
                        correct = True
                        print()
                        break

                    else:  # Opción tecleada por el usuario no es correcta
                        print("\x1b[1;31m" + "\n+ ERROR -->", "\x1b[1;35m" + "Opción inválida")

                    # Guardar las modificacióne de la creddencial y cifrar contenido
                    if correct:
                        seq_encryptacion(data_list, decrypt, usuario_log)

                        # Mensaje de credencial modificada correctamente
                        print("\x1b[0;32m" + "\n+ Credencial modificada correctamente\n")
                        break

            if not found: # El id introducido por el usuario no existe en la base de datos
                print("\x1b[1;31m" + "\n+ ERROR -->", "\x1b[1;35m" + "Id no encontrado\n")
                break

    else:  # El usuario no tiene credenciales guardadas en la base de datos
        print("\x1b[1;31m" + "\n+ ERROR -->", "\x1b[1;35m" + "El usuario no tiene credenciales")


if __name__ == '__main__':
    """Loop principal de la aplicación"""
    try:
        sys.tracebacklimit = 0  # Eliminar traceback en el reporte de errores
        usuario_log = None  # Variable para instanciar UserVariables cuando se inicia sesión
        app = True  # Variable para el loop principal de la aplicación
        session = False  # Variable para el loop principal de la sesión

        while app:
            # Mensaje de bienvenida con opciones
            print("\x1b[0;38m" + "Bienvenido a", "\x1b[3;34m" + "Theowall", "\x1b[0;38m" + """\b, tu gestor de contraseñas y documentos
    Si ya eres usuario -----""", "\x1b[0;34m" + "[1]",
                  "\x1b[0;38m" + "\n    Para registrarte -------", "\x1b[0;34m" + "[2]",
                  "\x1b[0;38m" + "\n    Cerrar aplicación ------", "\x1b[0;34m" + "[q]")

            yn = input("\x1b[0;38m" + "Elección: ")

            # Cerrar aplicación
            if yn == "q" or yn == "Q":
                print("\x1b[1;32m" + "\nCerrando la aplicación...\n")
                break

            else:
                if yn == "1":  # Iniciar sesión
                    u_usuario = input("\x1b[0;38m" + "\nUsuario: ")
                    u_pwd = input("\x1b[0;38m" + "Contraseña: ")
                    user_data, usuario_log = login(u_usuario, u_pwd)

                    if user_data == -1:
                        print("\x1b[1;31m" + "\n+ ERROR -->", "\x1b[1;35m" + "El usuario no existe\n")
                    else:
                        session = True

                elif yn == "2":  # Registrarse
                    user_data, usuario_log = signin()

                    # Control de errores al registrarse

                    if user_data == 0:  # Error en la validación de los parámetros
                        session = False

                    elif user_data == -3:  # El nombre del usuario de registro ya existe en la base de datos
                        print("\x1b[1;31m" + "\n+ ERROR -->", "\x1b[1;35m" + "El nombre de usuario ya existe\n")

                    elif user_data == -4:  # El email de registro ya existe en la base de datos
                        print("\x1b[1;31m" + "\n+ ERROR -->", "\x1b[1;35m" + "La dirección email ya está registrada\n")

                    else:  # Registrado correctamente y sesión abierta automáticamente
                        session = True

                else:  # Opción inválida
                    print("\x1b[1;31m" + "\n+ ERROR -->", "\x1b[1;35m" + "Opción inválida\n")

                while session and user_data != -1 and user_data != -2:  # Loop de sesión

                    # Panel de control
                    print("\x1b[0;38m" + """Panel de control (selecciona una opción):
    Editar una credencial --------""", "\x1b[0;34m" + "[1]",
                          "\x1b[0;38m" + "\n    Crear una nueva credencial ---", "\x1b[0;34m" + "[2]",
                          "\x1b[0;38m" + "\n    Eliminar una credencial ------", "\x1b[0;34m" + "[3]",
                          "\x1b[0;38m" + "\n    Editar perfil de usuario -----", "\x1b[0;34m" + "[4]",
                          "\x1b[0;38m" + "\n    Cerrar sesión ----------------", "\x1b[0;34m" + "[q]", )
                    modo = input("\x1b[0;38m" + "Elección: ")

                    if modo == "1":  # Editar una credencial
                        err = imprimir_credenciales(usuario_log)  # Se imprimen las creddenciales de usuario ya guardadas

                        if err != -1:  # Si el usuario tiene credenciales guardadas en la base de datos
                            modificar_credencial(usuario_log)

                    elif modo == "2":  # Crear una nueva una credencial
                        id_create = input("\x1b[0;38m" + "Id: ")
                        cred_create = input("\x1b[0;38m" + "Credencial: ")
                        data_create = {"id": id_create, "credencial": cred_create}
                        add_credential(data_create, usuario_log)

                    elif modo == "3":  # Eliminar una credencial

                        err = imprimir_credenciales(usuario_log) # Se imprimen las creddenciales de usuario ya guardadas

                        if err != -1:  # Si el usuario tiene credenciales guardadas en la base de datos
                            del_credential(usuario_log)

                    elif modo == "4": # Editar perfil de usuario
                        correct = False
                        while not correct:
                            list_user = list(user_data.items())
                            pss = "************************************************************************************"

                            # Se imprimen los datos del usuario (la contraseña no se muestra)
                            print("\nPerfil de " + usuario_log.NOMBRE.capitalize())
                            print("\x1b[0;34m" + "[1] ------ " + str(list_user[0][0]).capitalize() + ":", "\x1b[0;38m"
                                  + list_user[0][1])
                            print("\x1b[0;34m" + "[2] --- " + str(list_user[1][0]).capitalize() + ":", "\x1b[0;38m"
                                  + list_user[1][1])
                            print("\x1b[0;34m" + "[3] ----- " + str(list_user[2][0]).capitalize() + ":", "\x1b[0;38m"
                                  + list_user[2][1])
                            print("\x1b[0;34m" + "[4] ------- " + str(list_user[5][0]).capitalize() + ":", "\x1b[0;38m"
                                  + list_user[5][1])
                            print("\x1b[0;34m" + "[5] ---- " + str(list_user[7][0]).capitalize() + ":", "\x1b[0;38m"
                                  + pss[0:len(usuario_log.PASSWORD)])
                            print("\x1b[0;34m" + "[q] ------- Salir")

                            item = input("\x1b[0;38m" + "¿Qué quiere cambiar? Elección: ")
                            print()

                            if item == "1" or item == "2" or item == "3" or item == "4":  # Nombre, apellidos, usuario, email
                                correct = True
                                usuario_log, user_data = modificar_usuario(item, usuario_log, user_data)

                            elif item == "5":  # Password
                                correct = True

                                # Comprobar que el usuario sabe la contraseña maestra vigente antes de modificarla
                                pwd = input("\x1b[0;38m" + "Introduzca la contraseña anterior: ")
                                pwd_s = (pwd + usuario_log.SALT)
                                pwd_h = hash_pwd(pwd_s)

                                if pwd_h != list_user[7][1]:
                                    print("\x1b[1;31m" + "\n+ ERROR -->",
                                          "\x1b[1;35m" + "Contraseña incorrecta\n")
                                    break

                                usuario_log, user_data = modificar_usuario(item, usuario_log, user_data)

                            elif item == "q" or item == "Q":  # Salir
                                break

                            else:  # Opción no válida
                                print("\x1b[1;31m" + "+ ERROR -->", "\x1b[1;35m" + "Opción inválida")

                    elif modo == "q":  # Cerrar Sesión
                        print("\x1b[1;32m" + "\nCerrando la sesión...\n")
                        session = False
                        usuario_log = None
                        break

                    else: # Opción inválida
                        print("\x1b[1;31m" + "\n+ ERROR -->", "\x1b[1;35m" + "Opción inválida\n")

    except:  # Control de excepciones no previstas
        print("\x1b[1;31m" + "\n")
        raise Exceptions("\U000026A0 HA OCURRIDO UN ERROR \U000026A0") from None
