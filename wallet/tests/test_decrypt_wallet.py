import pytest
import os, sys

import decrypt_utc

def decrypt_v3_scrypt_aes_128_ctr():
    utc_file_name = 'test_v3_scrypt_aes_128_ctr_utc.json'
    with open('test_v3_scrypt_aes_128_ctr_pwd.txt') as pwd_fh:
        pwd = pwd_fh.read()
    print('pwd =', pwd)
    decrypt_utc_file(pwd, utc_file_name)
