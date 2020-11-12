package pem

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
)

func DecodeEcdsaPrivateKey(pemKey []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemKey)
	if block == nil || block.Type != TypePrivateKey {
		return nil, errors.New("Failed decode pem format private key info.")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.WithMessage(err, "Pem key bytes are not PKCS8 encoded ")
	}

	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("Pem key bytes do not contain an EC private key")
	}
	return priv, nil
}

func DecodeEcdsaPublicKey(pemKey []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemKey)
	if block == nil || block.Type != TypePublicKey {
		return nil, errors.New("Bytes are not PEM encoded")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.WithMessage(err, "Pem key bytes are not PKIX encoded ")
	}

	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Pem key bytes do not contain an EC private key")
	}
	return pub, nil
}

func EncodeEcdsaPrivateKey(priv *ecdsa.PrivateKey) []byte {
	pkcs8Encoded, _ := x509.MarshalPKCS8PrivateKey(priv)
	return pem.EncodeToMemory(&pem.Block{Type: TypePrivateKey, Bytes: pkcs8Encoded})
}

func EncodeEcdsaPublicKey(pub *ecdsa.PublicKey) []byte {
	pkixEncoded, _ := x509.MarshalPKIXPublicKey(pub)
	return pem.EncodeToMemory(&pem.Block{Type: TypePublicKey, Bytes: pkixEncoded})
}
