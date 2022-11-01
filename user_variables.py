"""Clase para guardar datos del usuario en una instancia cuando inicia sesión"""
class UserVariables:

    NOMBRE = ""
    APELLIDOS = ""
    USUARIO = ""
    NUM_USUARIO = 0
    SALT = ""
    NONCE = ""
    EMAIL = ""
    PADDING = ""
    PASSWORD = ""

    def __init__(self, data):
        self.NOMBRE = data["nombre"]
        self.APELLIDOS = data["apellidos"]
        self.USUARIO = data["usuario"]
        self.NUM_USUARIO = data["num_usuario"]
        self.SALT = data["salt"]
        self.NONCE = data["nonce"]
        self.EMAIL = data["email"]
        self.PADDING = data["padding"]
        self.PASSWORD = data["password"]
