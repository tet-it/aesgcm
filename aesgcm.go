package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"

	"github.com/pkg/errors"
)

var gcm cipher.AEAD

// New creates and initializes a new AesGcm service with the provided key.
//
// The key length must be 16, 24, or 32 bytes, corresponding to AES-128, AES-192, or AES-256.
func Init(key []byte) (err error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return ErrInvalidKeySize
	}

	// Create a new AES cipher block.
	block, err := aes.NewCipher(key)
	if err != nil {
		return errors.Wrap(err, ErrFailedToCreateAESCipher.Error())
	}

	// Create a new GCM from the cipher block.
	newGCM, err := cipher.NewGCM(block)
	if err != nil {
		return errors.Wrap(err, ErrFailedToCreateGCM.Error())
	}

	gcm = newGCM

	return nil
}

// Encrypt encrypts the provided plaintext using AES-GCM.
//
// The function generates a random nonce and includes it in the resulting ciphertext.
//
// Returns the ciphertext as a hexadecimal string.
func Encrypt(data []byte) (string, error) {
	// Generate a random nonce.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", errors.Wrap(err, ErrFailedToGenerateNonce.Error())
	}

	// Encrypt the data.
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the provided ciphertext, which must be a hexadecimal string.
//
// The function extracts the nonce from the ciphertext and uses it for decryption.
//
// Returns the original plaintext on success.
func Decrypt(cipherHexStr string) ([]byte, error) {
	// Decode the string into bytes.
	cipherText, err := hex.DecodeString(cipherHexStr)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode ciphertext")
	}

	// Validate the length of the data.
	if len(cipherText) < gcm.NonceSize() {
		return nil, ErrInvalidNonceSize
	}

	// Extract nonce and decrypt the data.
	nonce, ciphertext := cipherText[:gcm.NonceSize()], cipherText[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Wrap(err, ErrFailedToDecryptData.Error())
	}

	return plaintext, nil
}
