import hashlib
import random
import string

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def nonce(len=16):
    code_str = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.sample(code_str, len))

def padding(item, length):
        x = len(item)
        p = nonce(length-x)
        item = item + p
        return item


def symetric_encryption(data, key, iv):
    key_64 = padding(key, 64)
    data_bytes = bytes(data, 'utf-8')
    print(1)
    print(data_bytes)
    key = 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'
    key_bytes = bytes.fromhex(key)
    cipher = Cipher(algorithms.AES256(key_bytes), modes.CTR(iv))
    cipher2 = Cipher(algorithms.AES256(key_bytes), modes.CTR(iv))

    encryptor = cipher.encryptor()
    ct = encryptor.update(data_bytes) + encryptor.finalize()
    print(2)
    print(ct)

    return str(ct)


def symetric_decryption(data, key, iv):

    data_mod = data[2:-1]
    data_bytes_x = bytes(data_mod, 'utf-8')
    data_bytes = data_bytes_x.decode('unicode_escape').encode('latin1')

    key = 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'
    key_bytes = bytes.fromhex(key)

    cipher = Cipher(algorithms.AES256(key_bytes), modes.CTR(iv))

    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data_bytes) + decryptor.finalize()
    print(100)
    print(decrypted)


def hash_pwd(pwd):
    "Recibe la contraseña y devuelve el hash-SHA256"
    pwd_b = bytes(pwd, 'utf-8')
    hash = hashlib.sha256()
    hash.update(pwd_b)
    pwd_h = hash.hexdigest()
    return pwd_h