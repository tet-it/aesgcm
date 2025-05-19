package aesgcm

import "errors"

var (
	ErrInvalidKeySize          = errors.New("key must be 16, 24, or 32 bytes long")
	ErrInvalidNonceSize        = errors.New("invalid nonce size")
	ErrFailedToCreateAESCipher = errors.New("failed to create AES cipher")
	ErrFailedToCreateGCM       = errors.New("failed to create GCM")
	ErrFailedToGenerateNonce   = errors.New("failed to generate nonce")
	ErrFailedToDecryptData     = errors.New("failed to decrypt data")

	ErrFailedToGenerateKey = errors.New("failed to generate key")
)
