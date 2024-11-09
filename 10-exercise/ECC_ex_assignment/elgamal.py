from ecc import EC

class ElGamal(object):
    """ElGamal Encryption
    Public key encryption as replacing (mulmod, powmod) to (ec.add, ec.mul)
    - ec: elliptic curve
    - g: (random) a point on ec
    """
    
    def __init__(self, ec, g, n):
        """
        Initialize the ElGamal encryption with the elliptic curve, 
        base point g, and the order n of the curve.
        
        Parameters:
        - ec: an instance of EC representing the elliptic curve
        - g: a point on the elliptic curve
        - n: order of the elliptic curve
        
        >>> elgamal = ElGamal(ec_instance, g_point, n_order)
        >>> assert elgamal.ec == ec_instance
        >>> assert elgamal.g == g_point
        >>> assert elgamal.n == n_order
        """
        assert isinstance(ec, EC)
        assert ec.is_valid(g)
        self.ec = ec
        self.g = g
        self.n = n

    def gen(self, sk):
        """
        Generate public key.
        
        Parameters:
        - sk: private key as (random) int < ec.q
        
        Returns:
        - Randomized public key as a point on ec
        
        TODO:
        Exercise 1:
        
        Implement the missing method logic to properly randomize public key generation.
        The randomization should produce an integer that is large enough; for this, utilize 
        a random integer of at least 20 bits.
        
        This method should ensure that the key is securely randomized according to the
        lecture notes.
        """
        return self.ec.mul(self.g, sk)

    def enc(self, plaintext, pk, r):
        """
        Encrypt the plaintext using the public key and a random integer.
        
        Parameters:
        - plaintext: data as a point on ec
        - pk: public key as a point on ec
        - r: random int < ec.q
        
        Returns:
        - (ciphertext1, ciphertext2) as points on ec
        """
        assert self.ec.is_valid(plaintext)
        assert self.ec.is_valid(pk)
        return (self.ec.mul(self.g, r), self.ec.add(plaintext, self.ec.mul(pk, r)))

    def dec(self, ciphertext, sk):
        """
        Decrypt the ciphertext using the private key.
        
        Parameters:
        - ciphertext: (ciphertext1, ciphertext2) as points on ec
        - sk: private key as int < ec.q
        
        Returns:
        - plaintext as a point on ec
        """
        c1, c2 = ciphertext
        assert self.ec.is_valid(c1) and self.ec.is_valid(c2)
        return self.ec.add(c2, self.ec.neg(self.ec.mul(c1, sk)))

    def randomize_key(self, sk):
        """
        Randomizes secret key.
        
        Parameters:
        - sk: a secret key
        
        Returns:
        - A randomized key
        
        TODO:
        Exercise 1:
        
        Implement the method logic to properly randomize a secret key.
        
        This method should ensure that the key is securely randomized according to the
        lecture notes.
        """
        pass

    def random_ec_points(self):
        """
        Generates random elliptic curve points for point blinding countermeasure.

        Returns:
        - R: A point on the elliptic curve, modified based on a random choice.
        - S: Another point on the elliptic curve, modified similarly.

        TODO:
        Exercise 2:
        
        Implement the logic to randomize the generated elliptic curve points R and S,
        so that R andS randomly modified in each decryption operation, ensuring the blinding points
        vary each time.

        This can be implemented by, e.g., multiplying or negating the points based on the result of
        a coinflip, so that R and S remain on the elliptic curve.
        """
        # Hardcoded points for point blinding countermeasure:
        
        R = [
            42379038535447972425882922920705906187614560245489370485065143754481248749916, 
            7157235819141609872407131958606778042988197471338048906967563567681524627747
        ]
        S = [
            12023092955571775742129462795245908043695328604996865184404062632842725671078, 
            69719650118977673464433968526791304600352811755443486686633735756640764713805
        ]
        
        return R, S

    def blind_ciphertext(self, c1, R):
        """
        Applies point blinding to the ciphertext component c1.

        Parameters:
        - c1: Original ciphertext component as a point on the elliptic curve.
        - R: Precomputed blinding factor.

        Returns:
        - blind_c1: The blinded version of c1.

        TODO:
        Exercise 2:

        Implement the blinding for decryption.
        """
        pass

    def unblind_ciphertext(self, blind_c1, S, sk):
        """
        Unblinds a blinded point using the private key and blinding factor S.

        Parameters:
        - blinded_c1: The blinded version of c1.
        - sk: a secret key.
        - S: Precomputed blinding factor.

        Returns:
        - The unblinded point c1, ready for decryption.
        
        TODO:
        Exercise 2:
        
        Implement the unblinding for decryption.
        """
        
        pass


    def dec_point_blind(self, R, S, ciphertext, sk):
        """
        Decrypts a ciphertext using the the point blinding countermeasure.

        Parameters:
        - R: A point on the elliptic curve used for blinding.
        - S: A point on the elliptic curve used for blinding.
        - ciphertext: Tuple containing the blinded ciphertext (ciphertext1, ciphertext2).
        - sk: a secret key.

        Returns:
        - The original plaintext point on the elliptic curve.

        TODO:
        Exercise 2:

        Implement the point blinding countermeasure.

        This should utilize the methods `blind_ciphertext`
        and `unblind_ciphertext` while not affecting the
        input-output behaviour of the decryption.
        """

        pass # Remove once implemented

        c1, c2 = ciphertext
        assert self.ec.is_valid(c1) and self.ec.is_valid(c2)

        blind_c1 = self.blind_ciphertext(c1, R)
        unblind_c1 = self.unblind_ciphertext(blind_c1, S, sk)

        return self.ec.add(c2, self.ec.neg(unblind_c1))