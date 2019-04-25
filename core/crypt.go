package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

//HashFunc defines the hash function to be used in MAC generation
type HashFunc func() hash.Hash

//Verify defines an the MAC verification method
type Verify interface {
	VerifyHMAC(ciphertxt, mac, key []byte) bool
}

//Vault implements Verify interface
type Vault struct {
	Verify
}

//KeyStore stores the encryption and mac generation key
type KeyStore struct {
	Key []byte
}

//KeyGenerator defines the inputs for the key deriving function (PBKDF2)
type KeyGenerator struct {
	Password   []byte
	Salt       []byte
	Iterations int
	KeyLength  int
	HashFunc
}

//Encryptor encrypts the plaintext
type Encryptor struct {
	//Plaintext message to be encrypted
	Message string
	//Vault implements encrypt/decrypt utility methods
	Vault
}

//Decryptor decrypts the ciphertext
type Decryptor struct {
	//Cipher text to be decypted
	Ciphertext []byte
	//Vault implements encrypt/decrypt utility methods
	Vault
}

//NewKeyGen creates a new instance(pointer) of KeyGenerator
func NewKeyGen(password []byte, salt []byte, iterations int, keyLength int, hashFunc func() hash.Hash) *KeyGenerator {
	return &KeyGenerator{Password: password, Salt: salt, Iterations: iterations, KeyLength: keyLength, HashFunc: hashFunc}
}

//NewKeyStore creates a new instance (pointer) of KeyStore
func NewKeyStore(key []byte) *KeyStore {
	return &KeyStore{Key: key}
}

//HashPassword generates a 32 byte key for use in both AES256 encryption and HMAC_SHA256 mac generation
func (kg *KeyGenerator) HashPassword() []byte {
	return pbkdf2.Key(kg.Password, kg.Salt, kg.Iterations, kg.KeyLength, kg.HashFunc)
}

//VerifyHMAC compares MACs for validity in order to avoid timing side-channels.Generates the second ciphertext's MAC using the same key that generated the first ciphertext's MAC
func (v *Vault) verifyHMAC256(ciphertext, ciphertextMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(ciphertext)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(ciphertextMAC, expectedMAC)
}

//genHMAC256 generates a hash of the encrypted text
func (v *Vault) genHMAC256(ciphertext, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(ciphertext)
	hmac := mac.Sum(nil)
	return hmac
}

//Encrypt encrypts using the key from Hashpassword() then
//generates the mac of the encrypted text using GenHmac256
//and then appends the ciphertext to its mac
func (e *Encryptor) Encrypt(key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	plaintext := []byte(e.Message)

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	iv := ciphertext[:aes.BlockSize]
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	hmac := e.genHMAC256(ciphertext, key)

	ciphertext = append(hmac, ciphertext...)

	return ciphertext, nil
}

//Decrypt obtains the mac from the first 32 bytes of the ciphertext
//then checks whether its valid verifyHMAC().If it is valid it obtains
//the initialisation vector(16 bytes) also known as the nonce from the
//second batch of 32 bytes from the last byte position of the mac.It
//then obtains the ciphertext payload from the remaining slice of bytes:
//			ciphertext[48:].
//It is this ciphertext payload that is now XOR'd back to plaintext
func (d *Decryptor) Decrypt(key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	hmac := d.Ciphertext[0:32]

	if ok := d.verifyHMAC256(d.Ciphertext[32:], hmac, key); ok {
		//length of the mac = 32 bytes
		//length of the aes block = 16 bytes
		//iv = d.ciphertext(32:48) = 16 bytes
		iv := d.Ciphertext[len(hmac) : len(hmac)+aes.BlockSize]

		//len(d.ciphertext) = len(mac) + len(iv) + len(ciphertext_payload)
		plaintext := make([]byte, len(d.Ciphertext)-(len(hmac)+aes.BlockSize))

		stream := cipher.NewCTR(block, iv)

		//len(hmac)+aes.BlockSize = 48
		stream.XORKeyStream(plaintext, d.Ciphertext[len(hmac)+aes.BlockSize:])

		return plaintext, nil
	}
	hmacError := errors.New("Invalid hmac")

	return nil, hmacError

}
