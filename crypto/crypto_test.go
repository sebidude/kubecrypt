package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	encBytes   []byte
)

func TestGenerateKeyPair(t *testing.T) {
	privateKey, publicKey = GenerateKeyPair(1024)
	assert.IsType(t, rsa.PublicKey{}, *publicKey, "A rsa pub key must be generated.")
	assert.IsType(t, rsa.PrivateKey{}, *privateKey, "A rsa priv key must be generated.")
	assert.Equal(t, 128, privateKey.Size(), "Key must have size of 128 bit")
}

func TestEncrypt(t *testing.T) {
	encBytes = Encrypt(rand.Reader, publicKey, []byte("test-data"))
	assert.True(t, len(encBytes) > 0, "encBytes must be filled.")
}

func TestDecrypt(t *testing.T) {
	otherPrivateKey, _ := GenerateKeyPair(1024)

	t.Run("success", func(t *testing.T) {
		decBytes, err := Decrypt(rand.Reader, privateKey, encBytes)
		assert.NoError(t, err, "Decryption must not yield an error")
		assert.Equal(t, "test-data", string(decBytes), "Plaintext must match.")
	})

	t.Run("fail wrong key", func(t *testing.T) {
		_, err := Decrypt(rand.Reader, otherPrivateKey, encBytes)
		assert.Error(t, err, "Decryption must yield an error")
	})

	t.Run("fail short ciphertext", func(t *testing.T) {
		_, err := Decrypt(rand.Reader, otherPrivateKey, []byte("."))
		assert.Error(t, err, "Decryption must yield an error")
	})

}

func TestGenerateCertificate(t *testing.T) {
	cert, key, err := GenerateCertificate("cn", nil, time.Duration(5*time.Minute))
	assert.NoError(t, err, "Cert and key must be generated")
	assert.True(t, len(key) > 0, "key bytes must be filled.")
	assert.True(t, len(cert) > 0, "cert bytes must be filled.")

	pubkey := ReadPublicKeyFromCertPem(cert)
	assert.IsType(t, rsa.PublicKey{}, *pubkey, "Public key must be of type rsa.PublicKey")

	privkey, err := BytesToPrivateKey(key)
	assert.NoError(t, err, "Must get privkey from bytes.")
	assert.IsType(t, rsa.PrivateKey{}, *privkey, "Key must be of type rsa.PrivateKey")
}

func TestPublicKeyToBytes(t *testing.T) {

	t.Run("success", func(t *testing.T) {
		pubbytes, err := PublicKeyToBytes(publicKey)
		assert.NoError(t, err, "Must translate public key to bytes")
		assert.True(t, len(pubbytes) > 0, "pubbytes must be filled")
	})

	t.Run("fail nil pubkey", func(t *testing.T) {
		_, err := PublicKeyToBytes(nil)
		assert.Error(t, err, "Must yield error if not a pubkey")
	})
}

func TestReadPublicKeyFromFile(t *testing.T) {
	keyfile, err := os.Create("pubkey.pem")
	assert.NoError(t, err, "Must create new file.")

	keyBytes, err := PublicKeyToBytes(publicKey)
	assert.NoError(t, err, "Must get bytes from publicKey.")

	count, err := keyfile.Write(keyBytes)
	assert.NoError(t, err, "pubkey must be written to files")
	closeError := keyfile.Close()
	assert.NoError(t, closeError, "pubkeyfile must be closed")
	assert.Equal(t, len(keyBytes), count, "all bytes must be written to file")

	t.Run("fail not exist", func(t *testing.T) {
		_, err := ReadPublicKeyFromFile("nosuchfile")
		assert.Error(t, err, "Must yield error if file not found.")
	})

	t.Run("success", func(t *testing.T) {
		key, err := ReadPublicKeyFromFile("pubkey.pem")
		assert.NoError(t, err, "Must not yield error.")
		assert.IsType(t, rsa.PublicKey{}, *key, "Read key must be of type public key.")
	})
}

func TestReadPrivateKeyFromFile(t *testing.T) {
	keyfile, err := os.Create("privkey.pem")
	assert.NoError(t, err, "Must create new file.")

	keyBytes := PrivateKeyToBytes(privateKey)
	assert.NoError(t, err, "Must get bytes from privateKey.")

	count, err := keyfile.Write(keyBytes)
	assert.NoError(t, err, "privateKey must be written to files")
	closeError := keyfile.Close()
	assert.NoError(t, closeError, "keyfile must be closed")
	assert.Equal(t, len(keyBytes), count, "all bytes must be written to file")

	t.Run("fail not exist", func(t *testing.T) {
		_, err := ReadPrivateKeyFromFile("nosuchfile")
		assert.Error(t, err, "Must yield error if file not found.")
	})

	t.Run("success", func(t *testing.T) {
		key, err := ReadPrivateKeyFromFile("privkey.pem")
		assert.NoError(t, err, "Must not yield error.")
		assert.IsType(t, rsa.PrivateKey{}, *key, "Read key must be of type public key.")
	})
}

func TestCleanup(t *testing.T) {
	err := os.Remove("privkey.pem")
	assert.NoError(t, err, "file must be removed.")

	err = os.Remove("pubkey.pem")
	assert.NoError(t, err, "file must be removed.")
}
