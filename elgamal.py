"""
Normil Luccin
Elgamal Public-Key Encryption
April 1, 2024

This is a demo of the Elgamal Public-Key Encryption
"""

import random
from pyfinite import genericmatrix


class publicKey(object):
    def __init__(self, p=None, g=None, x=None, bits=0):
        self.p = p  # prime modulus
        self.g = g  # generator
        self.x = x  # public key
        self.bits = bits  # key size


class privateKey(object):
    def __init__(self, p=None, g=None, h=None, bits=0):
        self.p = p  # prime modulus
        self.g = g  # generator
        self.h = h  # private key
        self.bits = bits  # key size


def gcd(a, b):
    if a < b:
        return gcd(b, a)
    elif a % b == 0:
        return b
    else:
        return gcd(b, a % b)


# Miller-Rabin Primality Test
def isPrime(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # n should be d*(2^r) + 1
    r = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def generatePrime(bits):
    while True:
        a = random.getrandbits(bits)
        if isPrime(a):
            return a


def generateGenerator(p):
    for g in range(2, p):
        if pow(g, (p - 1) // 2, p) != 1 and pow(g, (p - 1) // 3, p) != 1:
            return g


def generateKeyPair(bits):
    p = generatePrime(bits)
    g = generateGenerator(p)
    h = random.randint(1, p - 2)  # private key
    x = pow(g, h, p)  # public key
    public_key = publicKey(p, g, x, bits)
    private_key = privateKey(p, g, h, bits)
    return public_key, private_key


def encrypt(publicKey, plaintext):
    p, g, x = publicKey.p, publicKey.g, publicKey.x
    k = random.randint(1, p - 2)  # Random secret key
    c1 = pow(g, k, p)
    c2 = [(ord(char) * pow(x, k, p)) % p for char in plaintext]
    return c1, c2


def decrypt(privateKey, ciphertext):
    p, h = privateKey.p, privateKey.h
    c1, c2 = ciphertext
    s = pow(c1, h, p)
    text = ''.join([chr((char * pow(s, -1, p)) % p) for char in c2])
    return text


if __name__ == "__main__":
    bits = int(input("Enter your key size in bits: "))
    plaintext = input("Enter plaintext (text only): ")

    public_key, private_key = generateKeyPair(bits)

    print("\n")
    print("Public key (p, g, x):", public_key.p, public_key.g, public_key.x)
    print("Private key (p, g, h):", private_key.p, private_key.g, private_key.h)
    print("\n")

    ciphertext = encrypt(public_key, plaintext)
    print("Encrypted ciphertext: ", ciphertext)
    decryptedCiphertext = decrypt(private_key, ciphertext)
    print("Decrypted plaintext: ", decryptedCiphertext)
