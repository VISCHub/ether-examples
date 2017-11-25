import os
import base64

with open('message.dec') as fh:
    words = fh.read().strip().split()

idx = 0
size = len(words)
num_parts = 4
num_elem_per_part = size // num_parts
part_count = 0
while idx < size:
    last_idx = min(idx + num_elem_per_part, size)
    part_words = words[idx:last_idx]
    print(base64.b64encode(os.urandom(24)))
    part_count += 1
    in_file_name = 'message_part_%d.in' % part_count
    out_file_name = 'message_part_%d.out' % part_count
    png_file_name = 'message_part_%d.png' % part_count
    with open(in_file_name, 'w') as fh:
        fh.write(' '.join(part_words))
    cmd = "openssl aes-128-ctr -salt -e -a -in %s -out %s"
    os.system(cmd % (in_file_name, out_file_name))
    os.unlink(in_file_name)
    os.system("qr < %s > %s" % (out_file_name, png_file_name))
    idx += num_elem_per_part
