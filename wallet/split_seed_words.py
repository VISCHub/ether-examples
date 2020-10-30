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
    print("Suggested random password: %s" % rand_pass)
    part_count += 1
    print("\nEncrypting the part #%d" % part_count)
    in_file_name = "message_part_%d.in" % part_count
    out_file_name = "message_part_%d.out" % part_count
    png_file_name = "message_part_%d.png" % part_count
    with open(in_file_name, "w") as fh:
        fh.write(" ".join(part_words))
    cmd = "openssl aes-128-ctr -salt -e -a -in %s -out %s"
    os.system(cmd % (in_file_name, out_file_name))
    os.unlink(in_file_name)
    os.system("qr < %s > %s" % (out_file_name, png_file_name))
    with open(out_file_name) as fh:
        content = fh.read().encode("utf-8")
        dgst = hashlib.sha256(content).hexdigest()
        print("SHA256 of the part #%d: %s" % (part_count, dgst))
    idx += num_elem_per_part
