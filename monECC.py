#!/usr/bin/env python3
# MonECC - Elliptic Curve Cryptography CLI tool
import sys
import argparse
from ecc import scalar_multiply
from key_manager import generate_keypair, write_private_key, write_public_key, read_private_key, read_public_key
from crypto_utils import derive_aes_key, aes_encrypt, aes_decrypt


def cmd_keygen(args):
    """Generate a keypair."""
    k, Q = generate_keypair(args.size)
    priv_file = f"{args.filename}.priv"
    pub_file = f"{args.filename}.pub"
    write_private_key(k, priv_file)
    write_public_key(Q, pub_file)
    print(f"Keys generated: {priv_file}, {pub_file}")


def cmd_crypt(args):
    """Encrypt a message with recipient's public key."""
    # Read recipient's public key
    Qb = read_public_key(args.key)

    # Generate ephemeral keypair
    k, Qa = generate_keypair()

    # Calculate shared secret S = k * Qb
    S = scalar_multiply(k, Qb)

    # Derive AES key
    iv, key = derive_aes_key(S)

    # Get plaintext
    if args.input:
        with open(args.input, 'r') as f:
            plaintext = f.read()
    else:
        plaintext = args.text

    # Encrypt
    ciphertext = aes_encrypt(plaintext, iv, key)

    # Output format: "Qax;Qay:ciphertext"
    output = f"{Qa[0]};{Qa[1]}:{ciphertext}"

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Encrypted message written to {args.output}")
    else:
        print(output)


def cmd_decrypt(args):
    """Decrypt a message with private key."""
    # Read private key
    k = read_private_key(args.key)

    # Get ciphertext
    if args.input:
        with open(args.input, 'r') as f:
            data = f.read().strip()
    else:
        data = args.text

    # Parse "Qax;Qay:ciphertext"
    qa_part, ciphertext = data.split(':')
    Qax, Qay = map(int, qa_part.split(';'))
    Qa = (Qax, Qay)

    # Calculate shared secret S = k * Qa
    S = scalar_multiply(k, Qa)

    # Derive AES key (same as encryption)
    iv, key = derive_aes_key(S)

    # Decrypt
    plaintext = aes_decrypt(ciphertext, iv, key)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(plaintext)
        print(f"Decrypted message written to {args.output}")
    else:
        print(plaintext)


def cmd_help(args=None):
    """Display help message."""
    help_text = """Script monECC par NITHARD Damien
Syntaxe :
    monECC <commande> [<cle>] [<texte>] [switchs]
Commande :
    keygen : Genere une paire de cle
    crypt : Chiffre <texte> pour la cle publique <cle>
    decrypt: Dechiffre <texte> pour la cle privee <cle>
    help : Affiche ce manuel
Cle :
    Un fichier qui contient une cle publique monECC ("crypt") ou une cle
    privee ("decrypt")
Texte :
    Une phrase en clair ("crypt") ou une phrase chiffree ("decrypt")
Switchs :
    -f <file> permet de choisir le nom des cles generes, monECC.pub et
    monECC.priv par defaut
    -s <size> permet de choisir la plage de generation de cle (1 a 1000 par defaut)
    -i <file> permet de lire le texte depuis un fichier
    -o <file> permet d'ecrire le resultat dans un fichier"""
    print(help_text)


def main():
    parser = argparse.ArgumentParser(add_help=False)
    subparsers = parser.add_subparsers(dest='command')

    # keygen
    keygen_parser = subparsers.add_parser('keygen')
    keygen_parser.add_argument('-f', '--filename', default='monECC')
    keygen_parser.add_argument('-s', '--size', type=int, default=1000)

    # crypt
    crypt_parser = subparsers.add_parser('crypt')
    crypt_parser.add_argument('key', help='Public key file')
    crypt_parser.add_argument('text', nargs='?', help='Plaintext')
    crypt_parser.add_argument('-i', '--input', help='Input file')
    crypt_parser.add_argument('-o', '--output', help='Output file')

    # decrypt
    decrypt_parser = subparsers.add_parser('decrypt')
    decrypt_parser.add_argument('key', help='Private key file')
    decrypt_parser.add_argument('text', nargs='?', help='Ciphertext')
    decrypt_parser.add_argument('-i', '--input', help='Input file')
    decrypt_parser.add_argument('-o', '--output', help='Output file')

    # help
    subparsers.add_parser('help')

    args = parser.parse_args()

    if args.command == 'keygen':
        cmd_keygen(args)
    elif args.command == 'crypt':
        if not args.text and not args.input:
            print("Error: text or -i required for crypt")
            sys.exit(1)
        cmd_crypt(args)
    elif args.command == 'decrypt':
        if not args.text and not args.input:
            print("Error: text or -i required for decrypt")
            sys.exit(1)
        cmd_decrypt(args)
    elif args.command == 'help':
        cmd_help()
    else:
        cmd_help()


if __name__ == '__main__':
    main()
