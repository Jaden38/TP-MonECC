# Elliptic Curve Cryptography operations
# Curve: Y² = X³ + 35X + 3 (mod 101)

A = 35
B = 3
P = 101  # Modulo
G = (2, 9)  # Generator point


def mod_inverse(a, p):
    """Extended Euclidean Algorithm to find modular inverse of a mod p."""
    if a < 0:
        a = a % p
    g, x, _ = extended_gcd(a, p)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {p}")
    return x % p


def extended_gcd(a, b):
    """Extended Euclidean Algorithm."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def point_add(p1, p2):
    """Add two points on the elliptic curve."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and y1 == y2:
        return point_double(p1)

    if x1 == x2 and y1 != y2:
        return None  # Point at infinity (inverse points)

    # s = (y2 - y1) / (x2 - x1) mod P
    s = ((y2 - y1) * mod_inverse(x2 - x1, P)) % P

    # x3 = s² - x1 - x2 mod P
    x3 = (s * s - x1 - x2) % P

    # y3 = s(x1 - x3) - y1 mod P
    y3 = (s * (x1 - x3) - y1) % P

    return (x3, y3)


def point_double(p1):
    """Double a point on the elliptic curve (2P)."""
    if p1 is None:
        return None

    x1, y1 = p1

    if y1 == 0:
        return None  # Tangent is vertical

    # s = (3 * x1² + A) / (2 * y1) mod P
    s = ((3 * x1 * x1 + A) * mod_inverse(2 * y1, P)) % P

    # x3 = s² - 2 * x1 mod P
    x3 = (s * s - 2 * x1) % P

    # y3 = s(x1 - x3) - y1 mod P
    y3 = (s * (x1 - x3) - y1) % P

    return (x3, y3)


def scalar_multiply(k, point):
    """Multiply a point by a scalar using Double-and-Add algorithm."""
    result = None  # Point at infinity
    addend = point

    while k:
        if k & 1:  # If lowest bit is 1
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1

    return result
