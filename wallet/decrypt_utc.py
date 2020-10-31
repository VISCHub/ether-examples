#!/usr/bin/env python

import binascii
import json
import getpass
import sys
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Hash import keccak


def kdf_scrypt(pwd, kdf_params):
    """
    Derive key using Scrypt. Accept KDF params from Ether UTC file.
    """
    # Convert salt from HEX to binary data
    salt = binascii.unhexlify(kdf_params["salt"])
    dklen = kdf_params["dklen"]
    N, r, p = kdf_params["n"], kdf_params["r"], kdf_params["p"]
    # Get derived key
    return scrypt(pwd, salt, key_len=dklen, N=N, r=r, p=p)


SUPPORTED_KDFS = {
    "scrypt": kdf_scrypt,
}


def decrypt_aes_128_ctr(pwd, utc_data):
    """
    Decrypt AES 128 CTR.
    Requires plain text password and Ether UTC file as JSON object.
    """
    # Decrypt
    utc_cipher_data = utc_data["Crypto"]
    # Check that we have supported KDF
    cur_kdf = utc_cipher_data["kdf"]
    assert cur_kdf in SUPPORTED_KDFS, f"Unsupported KDF: {cur_kdf}"

    kdf_params = utc_cipher_data["kdfparams"]
    # Delegate to the KDF
    derived_key = SUPPORTED_KDFS[cur_kdf](pwd, kdf_params)
    assert len(derived_key) == 32, f"Derived key: Expected length 32, got {len(derived_key)}"

    # Decryption key is only the first 16 bytes
    dec_key = derived_key[:16]
    # Convert cipher text from HEX to binary data
    cipher_text = binascii.unhexlify(utc_cipher_data["ciphertext"])
    # Convert IV from HEX to int
    aes_iv_int = int(utc_cipher_data["cipherparams"]["iv"], 16)
    counter = Counter.new(nbits=8, initial_value=aes_iv_int)
    cipher = AES.new(dec_key, AES.MODE_CTR, counter=counter)
    dec_priv_key = cipher.decrypt(cipher_text)

    # MAC in v3 is the KECCAK-256 of the last 16 bytes of the derived key and cipher text
    expected_mac = utc_cipher_data["mac"]
    keccak_256 = keccak.new(digest_bits=256)
    keccak_256.update(derived_key[-16:] + cipher_text)
    actual_mac = keccak_256.hexdigest()
    assert actual_mac == expected_mac, f"MAC error: Expected {expected_mac} != {actual_mac}"
    return dec_priv_key


SUPPORTED_CIPHERS = {
    "aes-128-ctr": decrypt_aes_128_ctr,
}


def decrypt_utc_file(pwd, utc_file_name):
    """
    Decrypt Ether UTC file. The password must be in plain text.
    """
    with open(utc_file_name, "r") as utc_fh:
        utc_data = json.load(utc_fh)

    utc_cipher_data = utc_data["Crypto"]
    cipher_name = utc_cipher_data["cipher"]

    # For this example, only AES 128 CTR is supported
    assert cipher_name in SUPPORTED_CIPHERS, f"Unsupported cipher: {cipher_name}"

    # Delegate decryption
    dec_priv_key = SUPPORTED_CIPHERS[cipher_name](pwd, utc_data)
    print("Successfully decrypted the UTC file: {utc_file_name}")
    return dec_priv_key


def decrypt_utc_file_hex_pwd(pwd_hex, utc_file_name):
    """
    Decrypt Ether UTC file. The password must be in HEX.
    """
    pwd = binascii.unhexlify(pwd_hex)
    decrypt_utc_file(pwd, utc_file_name)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write(f"Usage: {sys.argv[0]} UTC_JSON_file\n")
        sys.exit(1)
    print("Preparing to decrypt wallet from UTC file")
    utc_file_name = sys.argv[1]
    pwd_hex = None
    while not pwd_hex:
        pwd_hex = getpass.getpass("UTC file password in HEX: ")
    decrypt_utc_file_hex_pwd(pwd_hex, utc_file_name)
