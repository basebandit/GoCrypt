package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/basebandit/GoCrypt/crypt"
)

func main() {

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

	switch os.Args[1] {
	case "encrypt":
		encryptCmd.Parse(os.Args[2:])
	case "decrypt":
		decryptCmd.Parse(os.Args[2:])
	default:
		flag.PrintDefaults()
		os.Exit(1)
	}

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

		ciphertext := crypt.Encrypt(msg, pwd)

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
		plaintext := crypt.Decrypt(ciphertext, pwd)

		fmt.Printf("%s\n", plaintext)
	}

}
