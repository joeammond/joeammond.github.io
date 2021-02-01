#!/usr/bin/env python3

# Decrypt SPACE JACKAL's encrypted messages
#
# Joe Ammond (pugpug)

import sys

# Brute-force the solution to the equations:
# ((X * A) + (Y * B) + (Z * C)) & 0xFF == v1
# ((X * D) + (Y * E) + (Z * F)) & 0xFF == v2
# ((X * G) + (Y * H) + (Z * I)) & 0xFF == v3

def solve(v1, v2, v3, K):
    '''Solve 3 equations/3 unknowns. K = key, 9 bytes long'''
    
    A, B, C, D, E, F, G, H, I = K

    for X in range(255):
        for Y in range(255):
            for Z in range(255):
                if ((X * ord(A)) + (Y * ord(B)) + (Z * ord(C))) & 0xFF == v1 and \
                   ((X * ord(D)) + (Y * ord(E)) + (Z * ord(F))) & 0xFF == v2 and \
                   ((X * ord(G)) + (Y * ord(H)) + (Z * ord(I))) & 0xFF == v3:
                       return(X, Y, Z)


# Read the ciphertext from stdin, and convert from hex to bytes
C = sys.stdin.read()
C = bytes.fromhex(C)

# Key array
K = ''

# For each set of 3 key elements, solve for the known plaintext of 'SPACEARMY'
for i in range(3):
    k1, k2, k3 = solve(C[i], C[i+3], C[i+6], 'SPACEARMY')
    K = K + chr(k1) + chr(k2) + chr(k3)

print('Key values found:', ' '.join('%02x'%ord(K[i]) for i in range(len(K))))
print()

# Now we have the key, brute-force the message text from the ciphertext. Strip off the 
# 'SPACEARMY' header from the message first.

C = C[9:]

# Plaintext string
P = ''

for X, Y, Z in zip(*[iter(C)]*3):
    p1, p2, p3 = solve(X, Y, Z, K)
    P = P + chr(p1) + chr(p2) + chr(p3)

print(P)
