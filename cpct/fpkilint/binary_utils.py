import subprocess
import sys


def der2ascii(binary_der):
    if 'win' in sys.platform:
        completed_process = subprocess.run(["der2ascii.exe"], input=binary_der, stdout=subprocess.PIPE)
    else:
        completed_process = subprocess.run(["fpkilint/der2ascii"], input=binary_der, stdout=subprocess.PIPE)
    return completed_process.stdout.decode("utf-8")


