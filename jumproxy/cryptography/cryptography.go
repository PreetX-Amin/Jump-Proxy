package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"math/big"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

func checkError(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s\n", msg)
		panic(err)
	}
}

// Generate a salt value
func GenerateRandomSalt(length int) ([]byte, error) {
	results := make([]byte, length)
	for i := 0; i < length; i++ {
		salt, err := rand.Int(rand.Reader, big.NewInt(255))
		if err != nil {
			return nil, err
		}
		results[i] = byte(salt.Int64())
	}
	return results, nil
}

func GenerateAESGCMCipher(passphrase string, salt []byte) (cipher.AEAD, error) {
	// key := generatePDKDF2Package([]byte(passphrase), salt, 4096, 32)
	key := pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha512.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm, nil
}

func Encrypt(plaintext string, gcm cipher.AEAD) string {
	nonce := make([]byte, gcm.NonceSize())
	_, err := rand.Read(nonce)
	checkError(err, "Error generating nonce")
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return string(ciphertext)
}

func Decrypt(ciphertext string, gcm cipher.AEAD) string {
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		fmt.Println("Error decrypting message")
		return ""
	}

	return string(plaintext)
}
