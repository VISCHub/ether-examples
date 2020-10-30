#!/usr/bin/env python

import os
import base64
import hashlib

# This is work in progress. Don't expect clean code or test yet
# QR Code: https://pypi.python.org/pypi/qrcode

print("Decrypting the initial seed file")
dec_cmd = "openssl aes-128-ctr -d -a -in message.enc -out message.dec"
os.system(dec_cmd)

with open("message.dec") as fh:
    words = fh.read().strip().split()

os.unlink("message.dec")

idx = 0
size = len(words)
num_parts = 4
num_elem_per_part = size // num_parts
part_count = 0
while idx < size:
    last_idx = min(idx + num_elem_per_part, size)
    part_words = words[idx:last_idx]
    rand_pass = base64.b64encode(os.urandom(24))
    print(f"Suggested random password: {rand_pass}")
    part_count += 1
    print(f"\nEncrypting the part #{part_count}")
    in_file_name = f"message_part_{part_count}.in"
    out_file_name = f"message_part_{part_count}.out"
    png_file_name = f"message_part_{part_count}.png"
    with open(in_file_name, "w") as fh:
        fh.write(" ".join(part_words))
    cmd = f"openssl aes-128-ctr -salt -e -a -in {in_file_name} -out {out_file_name}"
    os.system(cmd)
    os.unlink(in_file_name)
    os.system(f"qr < {out_file_name} > {png_file_name}")
    with open(out_file_name) as fh:
        content = fh.read().encode("utf-8")
        dgst = hashlib.sha256(content).hexdigest()
        print(f"SHA256 of the part #{part_count}: {dgst}")
    idx += num_elem_per_part
