# Key generation and file management
import base64
import random
from ecc import G, scalar_multiply


def generate_keypair(size=1000):
    """Generate a keypair (private key k, public key Q = k*G)."""
    k = random.randint(1, size)
    Q = scalar_multiply(k, G)
    return k, Q


def write_private_key(k, filename="monECC.priv"):
    """Write private key to file in specified format."""
    encoded = base64.b64encode(str(k).encode()).decode()
    with open(filename, 'w') as f:
        f.write("---begin monECC private key---\n")
        f.write(f"{encoded}\n")
        f.write("---end monECC key---\n")


def write_public_key(Q, filename="monECC.pub"):
    """Write public key to file in specified format."""
    key_str = f"{Q[0]};{Q[1]}"
    encoded = base64.b64encode(key_str.encode()).decode()
    with open(filename, 'w') as f:
        f.write("---begin monECC public key---\n")
        f.write(f"{encoded}\n")
        f.write("---end monECC key---\n")


def read_private_key(filename):
    """Read private key from file."""
    with open(filename, 'r') as f:
        lines = f.readlines()

    if "---begin monECC private key---" not in lines[0]:
        raise ValueError("Invalid private key file format")

    encoded = lines[1].strip()
    k = int(base64.b64decode(encoded).decode())
    return k


def read_public_key(filename):
    """Read public key from file."""
    with open(filename, 'r') as f:
        lines = f.readlines()

    if "---begin monECC public key---" not in lines[0]:
        raise ValueError("Invalid public key file format")

    encoded = lines[1].strip()
    decoded = base64.b64decode(encoded).decode()
    Qx, Qy = map(int, decoded.split(';'))
    return (Qx, Qy)
