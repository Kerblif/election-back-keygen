package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

func writeFile(fileName string, data []byte) {
	file, err := os.Create(fileName)

	if err != nil {
		log.Println(err)
		return
	}

	_, err = file.Write(data)

	if err != nil {
		log.Println(err)
		return
	}
}

func ExportRsaPublicKeyAsPem(pubkey *rsa.PublicKey) ([]byte, error) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return []byte{}, err
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)

	return pubkey_pem, nil
}

func ExportRsaPrivateKeyAsPem(privkey *rsa.PrivateKey) []byte {
	privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkey_bytes,
		},
	)
	return privkey_pem
}

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		log.Println(err)
		return
	}

	publicKey := privateKey.PublicKey

	publicKeyPKIX, err := ExportRsaPublicKeyAsPem(&publicKey)

	if err != nil {
		log.Println(err)
		return
	}

	writeFile("./private.pem", ExportRsaPrivateKeyAsPem(privateKey))
	writeFile("./public.pem", publicKeyPKIX)
}
