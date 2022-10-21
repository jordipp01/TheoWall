
class UserVariables:

    NOMBRE = ""
    APELLIDOS = ""
    USUARIO = ""
    NUM_USUARIO = 0
    SALT = ""
    EMAIL = ""
    PASSWORD = ""

    def __init__(self, data):
        self.NOMBRE = data["nombre"]
        self.APELLIDOS = data["apellidos"]
        self.USUARIO = data["usuario"]
        self.NUM_USUARIO = data["num_usuario"]
        self.SALT = data["salt"]
        self.EMAIL = data["email"]
        self.PASSWORD = data["password"]
