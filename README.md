# MonECC

Auteur: NITHARD Damien M2 AL

## Description

Outil CLI de chiffrement/dechiffrement utilisant la cryptographie sur courbes elliptiques (ECC).

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Afficher l'aide
python monECC.py help

# Generer une paire de cles
python monECC.py keygen

# Chiffrer un message
python monECC.py crypt monECC.pub "Hello World"

# Dechiffrer un message
python monECC.py decrypt monECC.priv "<message_chiffre>"
```

## Options

- `-f <filename>` : nom personnalise pour les fichiers de cles
- `-s <size>` : plage de generation de cle (defaut: 1000)
- `-i <file>` : lire le texte depuis un fichier
- `-o <file>` : ecrire le resultat dans un fichier
