import json
import hashlib


def nuevo_usuario():
    nombre = input("Nombre: ")
    apellidos = input("Apellidos: ")
    usuario = input("Usuario: ")
    email = input("Email: ")
    pwd = input("Contraseña: ")
    pwd_b = bytes(pwd, 'utf-8')

    hash = hashlib.sha256()
    hash.update(pwd_b)
    pwd_h = hash.hexdigest()
    data = {"nombre": nombre, apellidos: "apellidos", "usuario": usuario, "email": email, "password": str(pwd_h)}
    add_item(data)
    #with open(self._FILE_PATH, "w", encoding="utf-8", newline="") as file:
    #    json.dump(data, file, indent=2)


def usuario():
    u_usuario = input("Usuario: ")
    pwd = input("Contraseña: ")
    pwd_b = bytes(pwd, 'utf-8')

    hash = hashlib.sha256()
    hash.update(pwd_b)
    u_pwd_h = hash.hexdigest()

    data_list = load()
    i=0
    x = False
    for i in range(0,len(data_list)):
        if u_usuario == data_list[i]["usuario"]:
            x = True
            if u_pwd_h == data_list[i]["password"]:
                print("Bienvenido")
            else:
                print("La contraseña no es correcta")
    if x == False:
        print("El usuario no existe")



def load():
    """Loading data into the datalist"""
    try:
        with open("data_file.json", "r", encoding="utf-8", newline="") as file:
            data_list = json.load(file)
            return data_list
    except:
        f = open("data_file.json", "w")
        data = []
        save(data)
        return data




def save(data_list):
    """Saves the datalist in the JSON file"""

    with open("data_file.json", "w", encoding="utf-8", newline="") as file:
        json.dump(data_list, file, indent=2)

def add_item(item):
    """Adds a new item to the datalist and updates the JSON file"""
    data_list = load()
    data_list.append(item)
    save(data_list)



print("Bienvenido a Theowall, tu gestor de contraseñas y documentos\n")
print("Si ya eres usuario, teclea [Y]")
print("para registrarte, teclea [N]")
yn = input()
i = False
while i != True:
    if yn == "y" or yn == "Y":
        i=True
        usuario()
    elif yn == "n" or yn == "N":
        i=True
        nuevo_usuario()
    else:
        print("Input incorrecto\n")
        print("Si ya eres usuario, teclea [Y]")
        print("Para registrarte, teclea [N]")
        yn = input()




