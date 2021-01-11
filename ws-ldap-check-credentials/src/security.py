from Crypto.Cipher import AES
import base64
import binascii
from typing import (
    Tuple,
    Text
)


key = b'Sixteen byte key'

encrypt_cipher = AES.new(
    key,
    AES.MODE_EAX
)
decrypt_cipher = AES.new(
    key,
    AES.MODE_EAX,
    nonce=encrypt_cipher.nonce
)


def crypt(value: str) -> bytes:
    ciphertext, tag = encrypt_cipher.encrypt_and_digest(value.encode('utf-8'))
    bytes_in_hex = binascii.hexlify(ciphertext)
    return bytes_in_hex


def decrypt(value_encrypted: str) -> str:
    value_encrypted_in_hex = value_encrypted.encode('utf-8')
    value_encrypted_in_bytes = binascii.unhexlify(value_encrypted_in_hex)
    value_decrypted = decrypt_cipher.decrypt(value_encrypted_in_bytes)
    return value_decrypted.decode('utf-8')


def convert_bytes_base_64(value_encrypted: bytes) -> str:
    return base64.b64encode(value_encrypted).decode('utf-8')


def decode_base_64(value: str) -> str:
    return base64.b64decode(value).decode('utf-8')


def seal_auth_b64(username: str, passwd: str) -> str:
    return base64.b64encode(f'{username}:{passwd}'.encode()).decode()


def unseal_auth_b64(auth_b64_seal: str) -> Tuple[Text, Text]:
    seal = base64.b64decode(auth_b64_seal.encode('utf-8'))
    username, password = seal.decode('utf-8').split(':')
    return username, password
