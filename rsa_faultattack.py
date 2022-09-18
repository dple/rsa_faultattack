from random import seed, randint
import math
from Crypto.Util import number
from rsacrt import RSA_CRT


def bit_flip(x, location):
    # Flip a bit of x at the 'location'
    return x ^ 2**location


def recover_privatekeys(m, s, e, N):
    # Given a faulty signature s, the message signed, and public keys. Recover private keys p & q
    p_rec = math.gcd(pow(s, e, N) - m, N)
    q_rec = N // p_rec

    return [p_rec, q_rec]


if __name__ == '__main__':

    l = 1024  # a toy modulus length. The recommended modulus length now is >= 2048

    # For an efficient computation, public key that could be as small as 3, 17 or 2^16 + 1.
    # However, as recommended in FIPS 186-4, e must be >= 2^16 and <= 2^256 to guarantee the security
    e = 3  # 65537 = 2^16 + 1

    rsa_sig = RSA_CRT(e, l)
    N, p, q = rsa_sig.private_keys

    print("p = ", p)
    print("q = ", q)
    print("N = ", N)

    msg = "A demo of fault injection attack against RSA-CRT Signature"  # message to be signed
    # Convert the signing message to long
    m = number.bytes_to_long(msg.encode())

    # In practice, message m should be hashed & padded by using OAEP or PSS to avoid small root attacks
    # Note that: padding using PKCS1 versions up to 1.5 is vulnerable to practical adaptive chosen-ciphertext attacks
    #                   (Bleichenbacher's attack at Crypto 1998)
    # PKCS v1.5 is vulnerable to forgery attack (Bleichenbacher's attack at Crypto 2006)
    s = rsa_sig.generate_signature(m, m)
    print("sp without error: ", s)

    # Inject a fault to the message
    seed(1)
    me = bit_flip(m, randint(0, 20))
    se = rsa_sig.generate_signature(m, me)
    print("sq with error: ", se)

    # Verify the correctness of the signature
    rsa_sig.verify_signature(m, s)  # correct signature
    rsa_sig.verify_signature(m, se)  # faulty signature

    # Recover the prime factors
    p_rec, q_rec = recover_privatekeys(m, se, e, N)

    if p == p_rec:
        print("Successfully recover p = ", p_rec)

    if q == q_rec:
        print("Successfully recover q = ", q_rec)
