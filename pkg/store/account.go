package store

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/registration"
)

var _ registration.User = &Account{}

type Account struct {
	Email        string                `json:"email,omitempty"`
	Registration *acme.ExtendedAccount `json:"registration,omitempty"`
	AccountKey   AccountKey            `json:"key,omitempty"`
}

func NewAccount(email string, privateKey crypto.Signer) *Account {
	return &Account{
		Email:        email,
		Registration: nil,
		AccountKey:   NewAccountKey(privateKey),
	}
}

func (u *Account) GetEmail() string {
	return u.Email
}
func (u Account) GetRegistration() *acme.ExtendedAccount {
	return u.Registration
}
func (u *Account) GetPrivateKey() crypto.Signer {
	return u.AccountKey.Key
}

var _ json.Marshaler = &AccountKey{}
var _ json.Unmarshaler = &AccountKey{}
var ErrUnknownPrivateKeyType = errors.New("unknown private key type")

type AccountKey struct {
	Key crypto.Signer
}

func (a *AccountKey) UnmarshalJSON(in []byte) error {
	var certStr string
	decerr := json.Unmarshal(in, &certStr)
	if decerr != nil {
		return decerr
	}

	keyBlock, _ := pem.Decode([]byte(certStr))

	var key crypto.Signer
	var err error
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		parsed, parseErr := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if parseErr != nil {
			return parseErr
		}
		var ok bool
		key, ok = parsed.(crypto.Signer)
		if !ok {
			return ErrUnknownPrivateKeyType
		}
	default:
		return ErrUnknownPrivateKeyType
	}
	if err != nil {
		return err
	}
	a.Key = key
	return nil
}

func (a *AccountKey) MarshalJSON() ([]byte, error) {
	certOut := &bytes.Buffer{}
	pemKey := certcrypto.PEMBlock(a.Key)
	err := pem.Encode(certOut, pemKey)
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(certOut.Bytes()))
}

func NewAccountKey(key crypto.Signer) AccountKey {
	return AccountKey{
		Key: key,
	}
}
