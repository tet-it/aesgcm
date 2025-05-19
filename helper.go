package aesgcm

import (
	"crypto/rand"

	"github.com/pkg/errors"
)

func GenerateAESKey(keySize int) ([]byte, error) {
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, ErrInvalidKeySize
	}

	key := make([]byte, keySize)

	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.Wrap(err, ErrFailedToGenerateKey.Error())
	}

	return key, nil
}
