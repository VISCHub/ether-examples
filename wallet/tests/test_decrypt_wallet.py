import pytest
import os, sys

from decrypt_utc import decrypt_utc_file

def test_decrypt_v3_scrypt_aes_128_ctr():
    utc_file_name = 'test_v3_scrypt_aes_128_ctr_utc.json'
    utc_pwd_file_name = 'test_v3_scrypt_aes_128_ctr_pwd.txt'
    with open(utc_pwd_file_name, 'r') as pwd_fh:
        pwd = pwd_fh.read().strip()
    print('pwd =', pwd)
    assert len(pwd) == 64
    decrypt_utc_file(pwd, utc_file_name)
