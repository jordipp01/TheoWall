import hashlib
import random
import string

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac


def nonce(length=16):
    """Crea un nonce aleatorio de un tamaño "length". Por defecto, el tamaño es 16"""
    code_str = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.sample(code_str, length))


def nonce_hex(length=16):
    """Crea un nonce en hexadecimal aleatorio de un tamaño "length". Por defecto, el tamaño es 16"""
    code_str = string.hexdigits + string.hexdigits + string.hexdigits + string.hexdigits + string.hexdigits
    return ''.join(random.sample(code_str, length))


def padding(item, length):
    """Genera un padding"""
    x = len(item)
    p = nonce_hex(length-x)
    return p


def symmetric_encryption(data, usuario_log):
    """Cifrado simétrico con AES-256 Mode CTR"""
    data_bytes = bytes(data, 'utf-8')

    key_bytes = key_transformation(usuario_log)

    iv = bytes(usuario_log.NONCE, 'utf-8')

    cipher = Cipher(algorithms.AES256(key_bytes), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(data_bytes) + encryptor.finalize()

    return str(ct)


def symmetric_decryption(data, usuario_log):
    """Descifrado simétrico con AES-256 Mode CTR"""
    data_mod = data[2:-1]
    data_bytes_x = bytes(data_mod, 'utf-8')
    data_bytes = data_bytes_x.decode('unicode_escape').encode('latin1')

    key_bytes = key_transformation(usuario_log)

    iv = bytes(usuario_log.NONCE, 'utf-8')

    cipher = Cipher(algorithms.AES256(key_bytes), modes.CTR(iv))

    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data_bytes) + decryptor.finalize()

    decrypted_mod = eval(decrypted)

    return decrypted_mod


def key_transformation(usuario_log):
    """Convierte una contraseña en formato string a bytes de la contraseña en hexadecimal más el padding"""
    key = usuario_log.PASSWORD
    key_b = key.encode('utf-8')
    key_hex = key_b.hex()
    key_hex_p = key_hex + usuario_log.PADDING
    key_bytes = bytes.fromhex(key_hex_p)
    return key_bytes


def hash_pwd(pwd):
    """Recibe la contraseña y devuelve el hash-SHA256"""
    pwd_b = bytes(pwd, 'utf-8')
    h = hashlib.sha256()
    h.update(pwd_b)
    pwd_h = h.hexdigest()
    return pwd_h


def hash_msg(msg, usuario_log):
    """Recibe el mensaje y devuelve el HMAC-SHA256"""
    msg_bytes = bytes(msg, 'utf-8')

    key = usuario_log.PASSWORD
    key_b = key.encode('utf-8')
    key_hex = key_b.hex()
    key_hex_p = key_hex + usuario_log.PADDING
    key_bytes = bytes.fromhex(key_hex_p)

    h = hmac.HMAC(key_bytes, hashes.SHA256())
    h.update(msg_bytes)
    msg_h = h.finalize()
    return msg_h.hex()
