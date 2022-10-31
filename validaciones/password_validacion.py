"""Clase para la validación de password"""
from .validaciones import Validaciones


class Password(Validaciones):
    """Clase para la validación de password"""
    _validation_pattern = r"^(?=.*\d)(?=.*[\u0021-\u002b\u003c-\u0040])(?=.*[A-Z])(?=.*[a-z])\S{8,16}$"
    _validation_error_message = """LA CONTRASEÑA NO CUMPLE LOS REQUISITOS: 
    Debe tener entre 8 y 16 caracteres, al menos un dígito, al menos una minúscula, 
    al menos una mayúscula y al menos un caracter no alfanumérico."""
