#!/usr/bin/env python3

# CATAPULT SPIDER malware protocol
#
# Joe Ammond (pugpug) @joeammond

import sys
from pwn import *

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512, SHA256, HMAC
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

# Create the HMAC and AES keys
salty_wow   = 'suchdoge4evawow'
hmac_wow    = 'such doge is yes wow'
aes_wow     = 'such doge is shibe wow'

hmac_key    = PBKDF2(hmac_wow, salty_wow, 16, count=4096, hmac_hash_module=SHA256)
aes_key     = PBKDF2(aes_wow, salty_wow, 16, count=4096, hmac_hash_module=SHA256)

# Who we communicate with
host = 'veryprotocol.challenges.adversary.zone'

# Client certificate and private key, from the malware executable
ssl_opts = {
    'keyfile':  'doge_key',
    'certfile': 'doge_cert',
}

# Encrypt the message, and prepend the HMAC
def encrypt(data):
    iv = b'\0' * 16
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)

    length = 16 - (len(data) % 16)
    data += bytes([length])*length

    enc = cipher.encrypt(data)

    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(enc)

    digest = hmac.digest()

    return (digest + enc)

# Decrypt the message, and verify that the HMAC matches
def decrypt(data):
    checksum = data[:32].hex()
    message = data[32:]

    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(message)

    verify = hmac.hexdigest()

    if checksum == verify:
        iv = b'\0' * 16
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        plaintext = cipher.decrypt(message)
        return(plaintext)
    else:
        return 'bonk'

# Main loop: read a DSON string, encrypt it, send it to the server,
# receive the response, print it. 
while True:

    # Read a string
    command = bytes(input('Shibe sez? ').strip(), 'utf-8')
    
    # Shibe sez quit
    if command == 'quit':
        sys.exit(0)

    # Connect to the server
    r = remote(host, 41414, ssl=True, ssl_args=ssl_opts)

    # Encrypt it
    ciphertext = encrypt(command)

    # Send the message length as u32, then the message
    length = p32(len(ciphertext), endianness="big", sign="unsigned")
    r.send(length)
    r.send(ciphertext)

    # Read the response length, and the message
    length = r.recv(4)
    response = r.recvall(timeout=5)
    r.close()

    # Decrypt the message and print it
    plaintext = decrypt(response)
    print(plaintext)
    print()

