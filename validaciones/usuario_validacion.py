"""Clase para la validación de usuario"""
from .validaciones import Validaciones


class Usuario(Validaciones):
    """Clase para la validación de usuario"""
    _validation_pattern = r"^([a-zA-Z@$#_0-9-]+){3,10}$"
    _validation_error_message = """EL NOMBRE DE USUARIO NO ES VÁLIDO:
    Debe tener entre 3 y 10 caracteres, 
    puede contener letras mayúsculas y minúsculas, 
    dígitos y los símbolos @ $ _ """