import subprocess
import sys
from asn1crypto import parser


def der2ascii(binary_der):
    if sys.platform == 'win32' or sys.platform == 'cygwin':
        completed_process = subprocess.run(["der2ascii.exe"], input=binary_der, stdout=subprocess.PIPE)
    elif sys.platform == 'darwin':
        completed_process = subprocess.run(["fpkilint/der2ascii.darwin"], input=binary_der, stdout=subprocess.PIPE)
    else:
        completed_process = subprocess.run(["fpkilint/der2ascii"], input=binary_der, stdout=subprocess.PIPE)
    return completed_process.stdout.decode("utf-8")


