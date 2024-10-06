from ecc import EC
from elgamal import ElGamal
import random

if __name__ == "__main__":
    # shared elliptic curve system of examples
    # parameters for the curve P-256
    ec = EC(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
            0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
            0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff)
    
    g = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
    n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    print("Order:", n)
    print("Generator:", ec.q)
    print("")
    assert n <= ec.q
 
    # ElGamal enc/dec usage
    eg = ElGamal(ec, g, n)              #set the EC, generator and order for the encryption scheme

    plaintext = ec.mul(g,random.randint(1,n-1))
    assert ec.is_valid(plaintext)
    print("Plaintext:", plaintext)
    print("")

    #Hard-coded secret key
    sk = 94952102889125874165031048266763684604430453914299026099439664202419944786514
    print("Secret key:", sk)
    print("")

    #Key generation
    pk = eg.gen(sk)
    assert ec.is_valid(pk)
    print("Public key:", pk)
    print("")

    #Encryption
    ciphertext = eg.enc(plaintext, pk, random.randint(1,n-1))

    #Decryption
    decoded = eg.dec(ciphertext, sk)

    print("Ciphertext:", ciphertext)
    print("")
    print("Recovered plaintext:", decoded)
    assert decoded == plaintext
    assert ciphertext != pk


    