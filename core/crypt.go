package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	b64 "encoding/base64"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

//hashPassword generates a 32 byte key for use in both AES256 encryption and HMAC_SHA256 mac generation
func hashPassword(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, 10000, 32, sha256.New)
}

//VerifyHMAC compares MACs for validity in order to avoid timing side-channels.Generates the second ciphertext's MAC using the same key that generated the first ciphertext's MAC
func verifyHMAC256(ciphertext, ciphertextMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(ciphertext)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(ciphertextMAC, expectedMAC)
}

//genHMAC256 generates a hash of the encrypted text
func genHMAC256(ciphertext, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(ciphertext)
	hmac := mac.Sum(nil)
	return hmac
}

//Encrypt encrypts using the key from Hashpassword() then
//generates the mac of the encrypted text using GenHmac256
//and then appends the ciphertext to its mac
func Encrypt(text string, passphrase string) string {

	//It is recommended that your salt be at least 8 bytes long
	salt := make([]byte, 8)
	_, err := rand.Read(salt)

	if err != nil {
		return err.Error()
	}

	key := hashPassword([]byte(passphrase), salt)
	block, err := aes.NewCipher(key)

	if err != nil {
		return err.Error()
	}

	plaintext := []byte(text)

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	iv := ciphertext[:aes.BlockSize]
	_, err = rand.Read(iv)
	if err != nil {
		return err.Error()
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	hmac := genHMAC256(ciphertext, key)

	ciphertext = append(hmac, ciphertext...)

	return b64.StdEncoding.EncodeToString([]byte("Gocrypt_" + string(salt) + string(ciphertext)))
}

//Decrypt obtains the mac from the first 32 bytes of the ciphertext
//then checks whether its valid verifyHMAC().If it is valid it obtains
//the initialisation vector(16 bytes) also known as the nonce from the
//second batch of 32 bytes from the last byte position of the mac.It
//then obtains the ciphertext payload from the remaining slice of bytes:
//			ciphertext[48:].
//It is this ciphertext payload that is now XOR'd back to plaintext
func Decrypt(encrypted string, passphrase string) string {
	ct, err := b64.StdEncoding.DecodeString(encrypted)

	if err != nil {
		return err.Error()
	}

	if string(ct[:8]) != "Gocrypt_" {
		return ""
	}

	salt := ct[8:16]
	ct = ct[16:]

	key := hashPassword([]byte(passphrase), salt)

	block, err := aes.NewCipher(key)

	if err != nil {
		return err.Error()
	}

	hmac := ct[0:32]

	if ok := verifyHMAC256(ct[32:], hmac, key); ok {
		//length of the mac = 32 bytes
		//length of the aes block = 16 bytes
		//iv = d.ciphertext(32:48) = 16 bytes
		iv := ct[len(hmac) : len(hmac)+aes.BlockSize]

		//len(d.ciphertext) = len(mac) + len(iv) + len(ciphertext_payload)
		plaintext := make([]byte, len(ct)-(len(hmac)+aes.BlockSize))

		stream := cipher.NewCTR(block, iv)

		//len(hmac)+aes.BlockSize = 48
		stream.XORKeyStream(plaintext, ct[len(hmac)+aes.BlockSize:])

		return string(plaintext)
	}
	hmacError := errors.New("Invalid hmac")

	return hmacError.Error()

}
