"""Clase para la validación de email"""
from .validaciones import Validaciones


class Email(Validaciones):
    """Clase para la validación de email"""
    _validation_pattern = r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$"
    _validation_error_message = "LA DIRECCIÓN EMAIL NO ES VÁLIDA"
