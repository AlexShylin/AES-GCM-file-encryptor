"""This module encrypts or decrypts file in AES GCM mode."""

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

from getpass import getpass
from json import dumps, loads
import sys

static_header = b"Si vis pacem, para bellum"
header_length = len(static_header)
nonce_length = 16
tag_length = 16
salt_length = 16

def encrypt(raw_input):
    # Key generation
    salt = get_random_bytes(salt_length)
    password = getpass()
    key = PBKDF2(password, salt)

    cipher = AES.new(key, AES.MODE_GCM, mac_len=tag_length)
    cipher.update(static_header)
    ciphertext, tag = cipher.encrypt_and_digest(raw_input)
    nonce = cipher.nonce

    mix = static_header + nonce + tag + salt + ciphertext
    return b64encode(mix)

def decrypt(encrypted_input):
    b = b64decode(encrypted_input)
    header = b[0:header_length]
    nonce = b[header_length:header_length + nonce_length]
    tag = b[header_length + nonce_length:header_length + nonce_length + tag_length]
    salt = b[header_length + nonce_length + tag_length:header_length + nonce_length + tag_length + salt_length]
    ciphertext = b[header_length + nonce_length + salt_length + tag_length:]

    # Key generation
    password = getpass()
    decryption_key = PBKDF2(password, salt)

    # Validate MAC and decrypt
    # If MAC validation fails, ValueError exception will be thrown
    cipher = AES.new(decryption_key, AES.MODE_GCM, nonce)
    cipher.update(header)
    try:
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data
    except ValueError as mac_mismatch:
        print("\nMAC validation failed during decryption. No authentication guarantees on this ciphertext")
        print("\nUnauthenticated Header: " + str(header))
        raise mac_mismatch

def read_file(path):
    with open(path, 'rb') as file:
        data = file.read()
    return data

def write_to_file(path, content):
    with open(path, "xb") as file:
        file.write(content)

def print_help():
    print("help stub")


if __name__ == '__main__':
    command_line_args = sys.argv
    if len(command_line_args) == 1:
        print_help()

    operation_type = command_line_args[1]
    if operation_type == "help":
        print_help()
    elif operation_type == "encrypt":
        if len(command_line_args) != 4:
            print("Invalid number of arguments", file=sys.stderr)
            print_help()
        else:
            input_file_path = command_line_args[2]
            output_file_path = command_line_args[3]
            input_file_content = read_file(input_file_path)
            encrypted_content = encrypt(input_file_content)
            write_to_file(output_file_path, encrypted_content)
    elif operation_type == "decrypt":
        if len(command_line_args) != 4:
            print("Invalid number of arguments", file=sys.stderr)
            print_help()
        else:
            input_file_path = command_line_args[2]
            output_file_path = command_line_args[3]
            input_file_content = read_file(input_file_path)
            decrypted_content = decrypt(input_file_content)
            write_to_file(output_file_path, decrypted_content)
    else:
        print("Unknown operation type", file=sys.stderr)
        print_help()
