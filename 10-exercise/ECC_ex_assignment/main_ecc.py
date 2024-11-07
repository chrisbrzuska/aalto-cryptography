from ecc import EC
from elgamal import ElGamal
import random

if __name__ == "__main__":
    # NOTE FOR STUDENTS:
    # Do NOT modify any of the variable values in this code.
    # These values are required for unit tests to pass correctly.

    # Parameters for the elliptic curve P-256
    curve_a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    curve_b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    curve_p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff

    # Initialize the elliptic curve
    ec = EC(curve_a, curve_b, curve_p)

    # Define generator point (g) on the elliptic curve
    g = (
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    )

    # Order of the group 
    n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    
    # Verify the order of the group
    print("Order of the group:", n)
    print("Field size of the curve (generator):", ec.q)
    print("")
    assert n <= ec.q

    # Initialize ElGamal encryption scheme with elliptic curve, generator point, and n
    eg = ElGamal(ec, g, n)

    # Generate a random plaintext point on the elliptic curve
    random_scalar = random.randint(1, n - 1)
    plaintext = ec.mul(g, random_scalar)
    
    # Ensure the plaintext is a valid point on the curve
    assert ec.is_valid(plaintext)
    print("Generated plaintext:", plaintext)
    print("")

    # Hard-coded secret key
    secret_key = 94952102889125874165031048266763684604430453914299026099439664202419944786514
    print("Secret key:", secret_key)
    print("")

    # Key generation (public key)
    public_key = eg.gen(secret_key)

    # Ensure the public key is valid
    assert ec.is_valid(public_key)
    print("Generated public key:", public_key)
    print("")

    # Encryption of the plaintext using the public key
    random_scalar_2 = random.randint(1, n - 1)
    ciphertext = eg.enc(plaintext, public_key, random_scalar_2)
    
    # Decryption using the secret key
    recovered_plaintext = eg.dec(ciphertext, secret_key)

    print("Ciphertext:", ciphertext)
    print("")
    print("Recovered plaintext:", recovered_plaintext)

    # Ensure the decryption recovered the original plaintext
    assert recovered_plaintext == plaintext
    assert ciphertext != public_key

    ##

    # Feel free to test your implementations for Exercise 1 and Exercise 2 here in a similar fashion!