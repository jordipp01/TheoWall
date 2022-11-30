import hashlib
import random
import string
import cryptography
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


def nonce(length=16):
    """Crea un nonce aleatorio de un tamaño "length". Por defecto, el tamaño es 16"""
    code_str = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.sample(code_str, length))


def nonce_hex(length=16):
    """Crea un nonce en hexadecimal aleatorio de un tamaño "length". Por defecto, el tamaño es 16"""
    code_str = string.hexdigits + string.hexdigits + string.hexdigits + string.hexdigits + string.hexdigits
    return ''.join(random.sample(code_str, length))


def padding_item(item, length):
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


def hash_file(file_b):
    h = hashlib.sha256()
    h.update(file_b)
    file_h = h.hexdigest()
    return bytes.fromhex(file_h)


def store_key(key, path):
    with open(path, "w+b") as file:
        file.write(key)
        file.close()


def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'26*Kw4lP')
    )

    store_key(pem, "keys/private_key.pem")

    public_key = private_key.public_key()
    pem2 = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    store_key(pem2, "keys/public_key.pem")


def load_priv_key(path):
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=b'26*Kw4lP',
        )
    return private_key

def load_pub_key(path):
    with open(path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read())
    return public_key


def store_signature(signature, usuario_log):
    path = "signatures/signature_" + usuario_log.USUARIO + ".pem"
    path_folder = 'signatures'
    folder_exists = os.path.exists(path_folder)
    if not folder_exists:
        os.mkdir(path_folder)
    with open(path, 'w+') as file:
        file.write(str(signature))
        file.close()


def signature(message, usuario_log):
    private_key = load_priv_key("keys/private_key.pem")
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    store_signature(signature, usuario_log)


def load_signature(path_signature):
    with open(path_signature, 'r') as file:
        signature = file.read()
        file.close()
        return eval(signature)


def verify_signature(message, path_signature):
    try:
        signature = load_signature(path_signature)
        private_key = load_priv_key("keys/private_key.pem")
        public_key = private_key.public_key()
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("\x1b[0;32m" + "\n+ Firma válida\n")

    except cryptography.exceptions.InvalidSignature:
        print("Firma inválida")
        print("\x1b[1;31m" + "\n+ LA FIRMA NO ES VÁLIDA\n")

    except FileNotFoundError:

        print("\x1b[1;31m" + "\n+ EL DOCUMENTO NO ESTÁ FIRMADO\n")



def load_file(path):
    with open(path, 'r') as f:
        file = f.read()
        f.close()
    return bytes(file, 'utf-8')

