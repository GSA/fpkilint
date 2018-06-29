import subprocess
import textwrap
import sys


def der2ascii(binary_der):
    if 'win' in sys.platform:
        completed_process = subprocess.run(["der2ascii.exe"], input=binary_der, stdout=subprocess.PIPE)
    else:
        completed_process = subprocess.run(["fpkilint/der2ascii"], input=binary_der, stdout=subprocess.PIPE)
    return completed_process.stdout.decode("utf-8")


def binary_to_hex_string(byte_value, multi_line=None):
    if not isinstance(byte_value, bytes):
        return "You must pass in bytes..."

    hex_string = ""

    if multi_line is not True:
        hex_string += ''.join('%02X' % c for c in byte_value)
    else:
        hex_string += textwrap.fill(' '.join('%02X' % c for c in byte_value), 43)

    return hex_string


def get_der_display_string(byte_value, preface=None, multi_line=None):
    if not isinstance(byte_value, bytes):
        return "You must pass in bytes..."

    if preface is None:
        der_display_string = "DER: "
    else:
        der_display_string = preface

    if multi_line is not True:
        der_display_string += binary_to_hex_string(byte_value)
    else:
        der_display_string += '\n'
        der_display_string += binary_to_hex_string(byte_value, True)

    return der_display_string

