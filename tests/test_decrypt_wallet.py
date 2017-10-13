import os, sys, binascii
import pytest

from wallet.decrypt_utc import decrypt_utc_file
from wallet.decrypt_utc import decrypt_utc_file_hex_pwd

params_v3_scrypt_aes_128_ctr = {
    'utc_file': 'tests/test_v3_scrypt_aes_128_ctr_utc.json',
    'pwd_file': 'tests/test_v3_scrypt_aes_128_ctr_pwd.txt',
}


def test_decrypt_v3_scrypt_aes_128_ctr():
    '''Test decryption on UTC json file encrypted with AES 128 CTR'''
    utc_file_name = params_v3_scrypt_aes_128_ctr['utc_file']
    utc_pwd_file_name = params_v3_scrypt_aes_128_ctr['pwd_file']

    with open(utc_pwd_file_name, 'r') as pwd_fh:
        pwd_hex = pwd_fh.read().strip()
    assert len(pwd_hex) == 64
    # Decrypt with HEX password
    decrypt_utc_file_hex_pwd(pwd_hex, utc_file_name)
    # Decrypt with plain text password
    pwd = binascii.unhexlify(pwd_hex)
    decrypt_utc_file(pwd, utc_file_name)
