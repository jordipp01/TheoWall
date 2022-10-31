"""Clase para la validación de nombre"""
from .validaciones import Validaciones


class Nombre(Validaciones):
    """Clase para la validación de nombre"""
    _validation_pattern = r"^([A-ZÁÉÍÓÚ]{1}[a-zñáéíóú]+[\s]*)+$"
    _validation_error_message = "EL NOMBRE NO ES VÁLIDO"
