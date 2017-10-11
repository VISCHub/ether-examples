import os, sys, binascii
import pytest

from decrypt_utc import decrypt_utc_file, decrypt_utc_file_hex_pwd

def test_decrypt_v3_scrypt_aes_128_ctr():
    utc_file_name = 'test_v3_scrypt_aes_128_ctr_utc.json'
    utc_pwd_file_name = 'test_v3_scrypt_aes_128_ctr_pwd.txt'

    with open(utc_pwd_file_name, 'r') as pwd_fh:
        pwd_hex = pwd_fh.read().strip()
    assert len(pwd_hex) == 64
    # Decrypt with HEX password
    decrypt_utc_file_hex_pwd(pwd_hex, utc_file_name)
    # Decrypt with plain text password
    pwd = binascii.unhexlify(pwd_hex)
    decrypt_utc_file(pwd, utc_file_name)
