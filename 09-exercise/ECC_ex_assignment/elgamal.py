from ecc import EC

class ElGamal(object):
    """ElGamal Encryption
    public key encryption as replacing (mulmod, powmod) to (ec.add, ec.mul)
    - ec: elliptic curve
    - g: (random) a point on ec
    """
    def __init__(self, ec, g, n):
        assert isinstance(ec, EC)
        assert ec.is_valid(g)
        self.ec = ec
        self.g = g
        self.n = n
        pass

    def gen(self, sk):
        """generate public key
        - sk: private key as (random) int < ec.q
        - returns: public key as a point on ec
        """
        return self.ec.mul(self.g, sk)

    def enc(self, plaintext, pk, r):
        """encrypt
        - plaintext: data as a point on ec
        - pk: public key as a point on ec
        - r: random int < ec.q
        - returns: (ciphertext1, cipertext2) as points on ec
        """
        assert self.ec.is_valid(plaintext)
        assert self.ec.is_valid(pk)
        return (self.ec.mul(self.g, r), self.ec.add(plaintext, self.ec.mul(pk, r)))

    def dec(self, ciphertext, sk):
        """decrypt
        - ciphertext: (ciphertext1, cipertext2) as points on ec
        - sk: private key as int < ec.q
        - returns: plaintext as a point on ec
        """
        c1, c2 = ciphertext
        assert self.ec.is_valid(c1) and self.ec.is_valid(c2)
        return self.ec.add(c2, self.ec.neg(self.ec.mul(c1, sk)))
    pass
