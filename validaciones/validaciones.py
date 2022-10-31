import re


class Validaciones:
    _validation_pattern = r""
    _validation_error_message = ""
    _value = ""

    def __init__(self, attr_value):
        self._value = self._validate(attr_value)

    @property
    def value(self):
        """returns the attribute value"""
        return self._value

    @value.setter
    def value(self, attr_value):
        self._value = self._validate(attr_value)

    def _validate(self, attr_value):
        """validates the attr_value """
        registration_type_pattern = re.compile(self._validation_pattern)
        res = registration_type_pattern.fullmatch(attr_value)
        if not res:
            print("\x1b[1;31m" + "\n+ " + self._validation_error_message + "\n")

            return -1
        return attr_value
