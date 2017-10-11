import os, sys

CUR_DIR=os.getcwd()
PARENT_DIR=os.path.abspath(os.path.join(CUR_DIR, os.pardir))

sys.path.append(PARENT_DIR)
