package main

import (
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"

	"github.com/basebandit/GoCrypt/core"
)

//Uninitialized KeyStore
var ks *core.KeyStore

var key []byte

func main() {

	//It is recommended that your salt be at least 8 bytes long
	salt := make([]byte, len("53cr37_s@l7"))
	_, err := rand.Read(salt)

	if err != nil {
		fmt.Println(err)
		return
	}

	//CLI Commands
	encryptCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
	decryptCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)

	//CLI subcommands
	encryptSrc := encryptCmd.String("s", "", "Plaintext to be encrypted.(Required)")
	encryptPwd := encryptCmd.String("p", "", "Encryption password.(Required)")
	decryptSrc := decryptCmd.String("s", "", "Ciphertext to be decrypted.(Required)")
	decryptPwd := decryptCmd.String("p", "", "Decryption password.(Required)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n\t\tencrypt Encrypt command\n\t\t\t-s [Source]Plaintext to be encrypted.(Required)\n\t\t\tp [Password] Encryption password.(Required)\n\t\tdecrypt Decrypt command\n\t\t\t -s [Source]Ciphertext to be decrypted.(Required)\n\t\t\tp [Password] Decryption password.(Required)\n", os.Args[0])

		flag.PrintDefaults()
	}

	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	// Switch on the subcommand
	// Parse the flags for appropriate FlagSet
	// FlagSet.Parse() requires a set of arguments to parse as input
	// os.Args[2:] will be all arguments starting after the subcommand at os.Args[1]
	switch os.Args[1] {
	case "encrypt":
		encryptCmd.Parse(os.Args[2:])
	case "decrypt":
		decryptCmd.Parse(os.Args[2:])
	default:
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Check which subcommand was Parsed using the FlagSet.Parsed() function. Handle each case accordingly.
	// FlagSet.Parse() will evaluate to false if no flags were parsed (i.e. the user did not provide any flags)
	if encryptCmd.Parsed() {
		var msg, pwd string
		// Required Flags
		if *encryptSrc == "" {
			encryptCmd.PrintDefaults()
			os.Exit(1)
		}
		msg = *encryptSrc

		if *encryptPwd == "" {
			encryptCmd.PrintDefaults()
			os.Exit(1)
		}
		pwd = *encryptPwd

		//First Step: Initialize a new KeyGenerator
		kg := core.NewKeyGen([]byte(pwd), []byte(salt), 10000, 32, sha256.New)

		//Second Step: Generate the key using the above KeyGenerator
		key = kg.HashPassword()

		if ks == nil {
			//Third Step: Store the generated Key for future use to encrypt/decrypt
			ks = core.NewKeyStore(key)
		}
		encryptor := core.Encryptor{Message: msg}
		//Fourth Step: Use the key
		ciphertext, err := encryptor.Encrypt(ks.Key)
		if err != nil {
			panic(err)
		}

		fmt.Printf("%s\n", ciphertext)
	}

	if decryptCmd.Parsed() {
		var ciphertext, pwd string
		// Required Flags
		if *decryptSrc == "" {
			decryptCmd.PrintDefaults()
			os.Exit(1)
		}
		ciphertext = *decryptSrc

		if *decryptPwd == "" {
			decryptCmd.PrintDefaults()
			os.Exit(1)
		}
		pwd = *decryptPwd
		// Print
		fmt.Printf("source: %s, password: %s\n", ciphertext, pwd)
		fmt.Println("Ks", ks)
		fmt.Println("Key", key)
	}
	fmt.Println("Key", key)
	// decryptor := core.Decryptor{Ciphertext: ciphertext}
	// plaintext, err := decryptor.Decrypt(ks.Key)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Printf("%s\n", plaintext)
}
