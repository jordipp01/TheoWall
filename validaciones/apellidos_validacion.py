"""Clase para la validación de apellidos"""
from .validaciones import Validaciones


class Apellidos(Validaciones):
    """Clase para la validación de apellidos"""
    _validation_pattern = r"^([a-zñáéíóúA-ZÁÉÍÓÚ]+[\s]*)+$"
    _validation_error_message = "LOS APELLIDOS NO SON VÁLIDOS"