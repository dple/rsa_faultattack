from Crypto.Util import number
from Crypto import Random
import Crypto
import math


class RSA_CRT:
    # Implementation of RSA signature based on Chinese Theorem Reminder (CRT)

    def __init__(self, e, modulus_length):
        self.modulus_length = modulus_length
        [p, q] = self.generate_keys(e)
        N = p * q
        self.private_keys = [N, p, q]
        self.public_keys = [N, e]

    def generate_keys(self, e):
        length = self.modulus_length
        p = number.getPrime(length, randfunc=Crypto.Random.get_random_bytes)
        # e and p - 1 must be co-prime
        while math.gcd(e, p - 1) != 1:
            p = number.getPrime(length, randfunc=Crypto.Random.get_random_bytes)

        # p and q should not be too close to avoid Fermat factorization. | p - q | >= 2 n ^ 1 / 4.
        # FIPS 186-4 recommends | p - q | >= 2 ^ {n / 2 - 100}.
        q = number.getPrime(p.bit_length() - 10, randfunc=Crypto.Random.get_random_bytes)
        # e and q - 1 must be co-prime
        while math.gcd(e, q - 1) != 1:
            q = number.getPrime(p.bit_length() - 10, randfunc=Crypto.Random.get_random_bytes)

        return [p, q]

    # Two parameters as message inputs is to simulate a fault injection attack into the
    #                      message in one of the two modular exponentiation
    def generate_signature(self, m1, m2):
        # Calculate two partial signatures
        N, p, q = self.private_keys
        N, e = self.public_keys
        dp = pow(e, -1, p - 1)
        dq = pow(e, -1, q - 1)
        qInv = pow(q, -1, p)

        # Calculate two partial signatures
        sp = pow(m1, dp, p)
        sq = pow(m2, dq, q)

        # Get the actual signature by combining partial signature
        h = (qInv * (sp - sq)) % p
        sig = sq + h * q  # the correct signature
        return sig

    def verify_signature(self, m, sig):
        N, e = self.public_keys
        if pow(sig, e, N) == m:
            print("The signature is correct")
        else:
            print("The signature is incorrect")
