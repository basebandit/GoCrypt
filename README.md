# GoCrypt

Encrypt text using AES-256 in counter mode (CTR)

## How It Works

- Encrypts a text file on a key generated on a user defined password and a randomly generated salt via key derivation function(PBKDF2).
- Appends to the resulting ciphertext a magic header, salt and its HMAC-SHA256 authentication tag.

## How to use it

```
$./gocrypt
Usage of ./gocrypt:
encrypt
      -s plaintext to be encrypted.(Required)
      -p encryption password.(Required)
decrypt
      -s ciphertext to be decrypted.(Required)
      -p decryption password.(Required)
```

### Encrypt command

```
$./gocrypt encrypt
  -p string
    	Encryption password.(Required)
  -s string
    	Plaintext to be encrypted.(Required)

$./gocrypt encrypt -s "Hello Basebandit" -p "t0p53cr37"
R29jcnlwdF+YftfvhJTEyXiCeeG4tM4OUOm/RTVttkw00Noryu9Vfl75VihLuw+anmNCGRUCl9WLZ4DlXFvoppIqhe3bvjnAWERcyL4qwPM=
```

### Decrypt command

```
$./gocrypt decrypt
  -p string
    	Decryption password.(Required)
  -s string
    	Ciphertext to be decrypted.(Required)

$./gocrypt decrypt -s "R29jcnlwdF+YftfvhJTEyXiCeeG4tM4OUOm/RTVttkw00Noryu9Vfl75VihLuw+anmNCGRUCl9WLZ4DlXFvoppIqhe3bvjnAWERcyL4qwPM=" -p "t0p53cr37"
Hello Basebandit
```

# This Code Has Not Been Reviewed By Any Expert Cryptographer. Use It At Your Own Peril.
