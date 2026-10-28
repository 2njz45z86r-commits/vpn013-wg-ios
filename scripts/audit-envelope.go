// Development evidence protection only. Standard-library X25519/HKDF/AES-GCM;
// never part of the application or the VPN protocol. No customer data/keys.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type envelope struct {
	Version                      int
	Ephemeral, Nonce, Ciphertext []byte
}

func must(err error) {
	if err != nil {
		panic("Audit evidence operation failed")
	}
}
func aead(shared []byte) cipher.AEAD {
	key, err := hkdf.Key(sha256.New, shared, nil, "VPN013 private development evidence v1", 32)
	must(err)
	block, err := aes.NewCipher(key)
	must(err)
	gcm, err := cipher.NewGCM(block)
	must(err)
	return gcm
}
func main() {
	if len(os.Args) != 4 {
		panic("Expected mode and two paths")
	}
	switch os.Args[1] {
	case "generate":
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		must(err)
		must(os.WriteFile(os.Args[2], key.Bytes(), 0600))
		must(os.WriteFile(os.Args[3], []byte(base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())), 0644))
		fmt.Println("Ephemeral evidence recipient generated; private material not printed")
	case "encrypt":
		public, err := os.ReadFile(os.Args[2])
		must(err)
		bytes, err := base64.StdEncoding.DecodeString(string(public))
		must(err)
		recipient, err := ecdh.X25519().NewPublicKey(bytes)
		must(err)
		ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
		must(err)
		shared, err := ephemeral.ECDH(recipient)
		must(err)
		box := aead(shared)
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 128*1024*1024+1))
		must(err)
		if len(raw) > 128*1024*1024 {
			panic("Oversized evidence")
		}
		nonce := make([]byte, box.NonceSize())
		_, err = rand.Read(nonce)
		must(err)
		result, err := json.Marshal(envelope{1, ephemeral.PublicKey().Bytes(), nonce, box.Seal(nil, nonce, raw, []byte("VPN013-audit-v1"))})
		must(err)
		must(os.WriteFile(os.Args[3], result, 0600))
		fmt.Println("Encrypted dependency evidence retained")
	case "decrypt":
		private, err := os.ReadFile(os.Args[2])
		must(err)
		key, err := ecdh.X25519().NewPrivateKey(private)
		must(err)
		raw, err := io.ReadAll(os.Stdin)
		must(err)
		var value envelope
		must(json.Unmarshal(raw, &value))
		if value.Version != 1 {
			panic("Unsupported evidence")
		}
		public, err := ecdh.X25519().NewPublicKey(value.Ephemeral)
		must(err)
		shared, err := key.ECDH(public)
		must(err)
		box := aead(shared)
		plain, err := box.Open(nil, value.Nonce, value.Ciphertext, []byte("VPN013-audit-v1"))
		must(err)
		must(os.WriteFile(os.Args[3], plain, 0600))
		fmt.Println("Evidence decrypted into private local report")
	default:
		panic("Unknown mode")
	}
}
