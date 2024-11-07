# Basics of Elliptic Curve Cryptography implementation on Python
from utils.inversion import Inverse
from utils.math_utils import MathUtil

class EC(object):
    """System of Elliptic Curve"""
    
    def __init__(self, a, b, q):
        """Initialize the elliptic curve with parameters a, b, and q.
        
        The elliptic curve is defined by the equation:
        (y**2 = x**3 + a * x + b) mod q
        
        Parameters:
        - a, b: parameters of the curve formula
        - q: prime number

        >>> assert 0 < a and a < q and 0 < b and b < q and q > 2
        >>> assert (4 * (a ** 3) + 27 * (b ** 2))  % q != 0
        """
        self.a = a
        self.b = b
        self.q = q
        # Unique zero value representation for "add" (not on the curve)
        self.zero = [0, 0]

    def is_valid(self, p):
        """Check if the point p is valid on the curve."""
        if p == self.zero: 
            return True
        
        l = (p[1] ** 2) % self.q
        r = ((p[0] ** 3) + self.a * p[0] + self.b) % self.q
        return l == r

    def at(self, x):
        """Find points on the curve at a given x-coordinate.
        
        Parameters:
        - x: int < q
        
        Returns:
        - ((x, y), (x, -y)) or raises an exception if not found.
        
        >>> a, ma = ec.at(x)
        >>> assert a[0] == ma[0] and a[0] == x
        >>> assert a[0] == ma[0] and a[0] == x
        >>> assert ec.neg(a) == ma
        >>> assert ec.is_valid(a) and ec.is_valid(ma)
        """
        assert x < self.q
        
        ysq = (x ** 3 + self.a * x + self.b) % self.q
        y, my = MathUtil().sqrt(ysq, self.q)
        
        return [x, y], [x, my]

    def neg(self, p):
        """Negate the point p.
        
        Returns:
        - The negated point.
        
        >>> assert ec.is_valid(ec.neg(p))
        """
        return [p[0], -p[1] % self.q]

    def add(self, p1, p2):
        """Add two points p1 and p2 on the elliptic curve.
        
        Returns:
        - The resulting point from the addition of p1 and p2.
        
        >>> d = ec.add(a, b)
        >>> assert ec.is_valid(d)
        >>> assert ec.add(d, ec.neg(b)) == a
        >>> assert ec.add(a, ec.neg(a)) == ec.zero
        >>> assert ec.add(a, b) == ec.add(b, a)
        >>> assert ec.add(a, ec.add(b, c)) == ec.add(ec.add(a, b), c)
        """
        if p1 == self.zero: 
            return p2
        if p2 == self.zero: 
            return p1
        
        if p1[0] == p2[0] and (p1[1] != p2[1] or p1[1] == 0):
            # p1 + -p1 == 0
            return self.zero
        
        if p1[0] == p2[0]:
            # p1 + p1: use tangent line of p1 as (p1, p1) line
            l = (3 * p1[0] * p1[0] + self.a) * Inverse().inv(2 * p1[1], self.q) % self.q
        else:
            l = (p2[1] - p1[1]) * Inverse().inv(p2[0] - p1[0], self.q) % self.q
        
        x = (l * l - p1[0] - p2[0]) % self.q
        y = (l * (p1[0] - x) - p1[1]) % self.q
        
        return [x, y]

    def mul(self, p, n):
        """Multiply point p by n using elliptic curve multiplication.
        
        Returns:
        - The resulting point from the multiplication of p by n.
        
        >>> m = ec.mul(p, n)
        >>> assert ec.is_valid(m)
        >>> assert ec.mul(p, 0) == ec.zero
        """
        r = self.zero
        m2 = p
        
        # O(log2(n)) addition using a doubling method for efficiency.
        # The following loop (O(n)) would naively add the point p to itself n times:
        #
        # for i in range(n):
        #     r = self.add(r, p)
        #     pass

        while n > 0:
            if n & 1 == 1:
                r = self.add(r, m2)
            n, m2 = n >> 1, self.add(m2, m2)
        
        return r

    def order(self, g):
        """Calculate the order of point g.
        
        Returns:
        - The order of the point g.
        
        >>> o = ec.order(g)
        >>> assert ec.is_valid(a) and ec.mul(a, o) == ec.zero
        >>> assert o <= ec.q
        """
        assert self.is_valid(g) and g != self.zero
        
        for i in range(1, self.q + 1):
            if self.mul(g, i) == self.zero:
                return i
            
        raise Exception("Invalid order")
