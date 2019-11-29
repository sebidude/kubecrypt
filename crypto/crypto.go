package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"time"
)

var (
	label = []byte("9c96d939c7f30920e17c18d7e97cc7e85a2f03d78c6b563ff38964ee02477d94")
)

func Decrypt(rnd io.Reader, privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 2 {
		return nil, fmt.Errorf("ciphertext is too short")
	}
	rsaLen := int(binary.BigEndian.Uint16(ciphertext))
	if len(ciphertext) < rsaLen+2 {
		return nil, fmt.Errorf("ciphertext is too short")
	}

	rsaCipher := ciphertext[2 : rsaLen+2]
	aesCipher := ciphertext[rsaLen+2:]

	sessionKey, err := rsa.DecryptOAEP(sha256.New(), rnd, privKey, rsaCipher, label)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	aed, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	zeroNonce := make([]byte, aed.NonceSize())

	plaintext, err := aed.Open(nil, zeroNonce, aesCipher, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func Encrypt(rnd io.Reader, pubKey *rsa.PublicKey, plaintext []byte) []byte {
	// Generate a random symmetric key
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(rnd, sessionKey); err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		panic(err)
	}

	aed, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	rsaCiphertext, err := rsa.EncryptOAEP(sha256.New(), rnd, pubKey, sessionKey, label)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, 2)
	binary.BigEndian.PutUint16(ciphertext, uint16(len(rsaCiphertext)))
	ciphertext = append(ciphertext, rsaCiphertext...)

	zeroNonce := make([]byte, aed.NonceSize())

	ciphertext = aed.Seal(ciphertext, zeroNonce, plaintext, nil)

	return ciphertext
}

// GenerateKeyPair generates a new key pair
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return privkey, &privkey.PublicKey
}

func GenerateCertificate(cn string, orgs []string, lifetime time.Duration) ([]byte, []byte, error) {

	privkey, pubkey := GenerateKeyPair(4096)

	notBefore := time.Now()
	notAfter := notBefore.Add(lifetime)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	certTmpl := x509.Certificate{
		SerialNumber: serialNumber,

		NotBefore: notBefore,
		NotAfter:  notAfter,
		IsCA:      true,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	if len(cn) > 0 {
		certTmpl.Subject.CommonName = cn
	} else {
		certTmpl.Subject.CommonName = "kubecrypt encryption certificate"
	}

	if len(orgs) > 0 {
		certTmpl.Subject.Organization = orgs
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &certTmpl, &certTmpl, pubkey, privkey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	certBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes := PrivateKeyToBytes(privkey)
	return certBytes, keyBytes, nil

}

func ReadPublicKeyFromCertPem(certpem []byte) *rsa.PublicKey {
	// parse the pubkey from the cert
	block, _ := pem.Decode(certpem)
	var cert *x509.Certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
	return rsaPublicKey
}

func ReadPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	keybytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	key, err := BytesToPrivateKey(keybytes)
	return key, err
}

func ReadPublicKeyFromFile(filename string) (*rsa.PublicKey, error) {
	keybytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	key, err := BytesToPublicKey(keybytes)
	return key, err
}

// PrivateKeyToBytes private key to bytes
func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	return privBytes
}

// PublicKeyToBytes public key to bytes
func PublicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes, nil
}

// BytesToPrivateKey bytes to private key
func BytesToPrivateKey(priv []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// BytesToPublicKey bytes to public key
func BytesToPublicKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		panic("cannot type cast key into rsa public key")
	}
	return key, nil
}
