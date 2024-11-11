from ecc import EC

class ElGamal(object):
    """ElGamal Encryption
    Public key encryption as replacing (mulmod, powmod) to (ec.add, ec.mul) compared to RSA
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
        
        # Starting points for point blinding countermeasure:
        
        self.R = [
            42379038535447972425882922920705906187614560245489370485065143754481248749916, 
            7157235819141609872407131958606778042988197471338048906967563567681524627747
        ]
        self.S = [
            12023092955571775742129462795245908043695328604996865184404062632842725671078, 
            69719650118977673464433968526791304600352811755443486686633735756640764713805
        ]

    def gen(self, sk):
        """
        Generate public key.
        
        Parameters:
        - sk: private key as (random) int < ec.q
        
        Returns:
        - Randomized public key as a point on ec
        
        TODO:
        Exercise 1:
        
        If you think that key generation should use key randomization, implement 
        the randomize_key(self, sk) procedure (further down in the code) and use the
        randomize_key(self, sk) method here, else delete this TODO.
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

        TODO:
        Exercise 1:
        
        If you think that encryption should use key randomization, implement 
        the randomize_key(self, sk) procedure (further down in the code) and use the
        randomize_key(self, sk) method here, else delete this TODO.
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
        TODO:
        Exercise 1:
        
        If you think that decryption should use key randomization, implement 
        the randomize_key(self, sk) procedure (further down in the code) and use the
        randomize_key(self, sk) method here, else delete this TODO.
        
        TODO:
        Exercise 3:
        Implement point blinding in decryption, implement the following procedures (defined further down in the code)
        - random_ec_points
        - dec_point_blind
        and use them to implement decryption with point blinding.
        
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
        lecture notes. Use at least a 20-bit integer for randomization.
        """
        pass

    def random_ec_points(self):
        """
        Randomizes random elliptic curve points for point blinding countermeasure.

        Returns:
        - R: A point on the elliptic curve, modified based on a bit flip.
        - S: Another point on the elliptic curve, modified  based on the same bit flip.
        - Updates the state variables self.R and self.S with the new values

        TODO:
        Exercise 3:
        
        Implement the above sketched logic to randomize the generated elliptic curve points R and S,
        so that R and S are randomly modified each time random_ec_points is called, ensuring the blinding points
        vary each time decryption is called (and make decryption call random_ec_points).
        """
        
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
        Exercise 3:

        Implement the ciphertext blinding algorithm blind_ciphertext.
        """
        pass # Remove once implemented

    def unblind_plaintext(self, blind_c1, S, sk):
        """
        Decrypts the blinded ciphertext using the private key and then unblinds 
        the result using the unblinding term S.

        Parameters:
        - blinded_c1: The blinded version of c1.
        - sk: a secret key.
        - S: Precomputed unblinding term.

        Returns:
        - The unblinded point c1, ready for decryption.
        
        TODO:
        Exercise 3:
        
        Implement the unblinding for decryption.
        """
        
        pass # Remove once implemented


    def dec_point_blind(self, R, S, ciphertext, sk):
        """
        Decrypts a ciphertext using the the point blinding countermeasure.
        This algorithm is called by dec, and should return the plaintext, but in addition to
        ciphertext and secret-key, it also gets the two points R and S for blinding and unblinding.

        Parameters:
        - R: A point on the elliptic curve used for blinding.
        - S: A point on the elliptic curve used for unblinding.
        - ciphertext: Tuple containing the blinded ciphertext (ciphertext1, ciphertext2).
        - sk: a secret key.

        Returns:
        - The original plaintext point on the elliptic curve.

        TODO:
        Exercise 3:

        Implement dec_point_blind.

        This should utilize the methods `blind_ciphertext`
        and `unblind_plaintext` while recovering the correct plaintext.
        """

        pass # Remove once implemented

        c1, c2 = ciphertext
        assert self.ec.is_valid(c1) and self.ec.is_valid(c2)

        blind_c1 = self.blind_ciphertext(c1, R)
        unblind_c1 = self.unblind_ciphertext(blind_c1, S, sk)

        return self.ec.add(c2, self.ec.neg(unblind_c1))