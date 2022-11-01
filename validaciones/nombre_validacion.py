"""Clase para la validación de nombre"""
from .validaciones import Validaciones


class Nombre(Validaciones):
    """Clase para la validación de nombre"""
    _validation_pattern = r"^([a-zñáéíóúA-ZÁÉÍÓÚ]+[\s]*)+$"
    _validation_error_message = """EL NOMBRE NO ES VÁLIDO"""
