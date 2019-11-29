package kube

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/sebidude/kubecrypt/crypto"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestInitKubecryptSecret(t *testing.T) {
	cert, key, err := crypto.GenerateCertificate("test", nil, time.Duration(10*time.Minute))
	assert.NoError(t, err, "Cert and key must be generated")

	t.Run("success", func(t *testing.T) {
		initError := InitKubecryptSecret(nil, key, cert, "", "secret.yaml", true)
		assert.NoError(t, initError, "Secret must be generated")
	})

	t.Run("fail already exist", func(t *testing.T) {
		initError := InitKubecryptSecret(nil, key, cert, "", "secret.yaml", true)
		assert.Error(t, initError, "Secret must not be overridden")
	})

}

func TestSecretFromManifestBytes(t *testing.T) {
	secretBytes, err := ioutil.ReadFile("secret.yaml")
	assert.NoError(t, err, "File secret.yaml must be read.")

	s, err := SecretsFromManifestBytes(secretBytes)
	assert.NoError(t, err, "Secret must be read from secret.yaml")
	assert.Equal(t, "Secret", s.TypeMeta.Kind, "Object must be of type Secret.")
	assert.Equal(t, corev1.SecretType("kubernetes.io/tls"), s.Type, "Secret must be of type kubernetes.io/tls.")

}

func TestNewSecret(t *testing.T) {
	data := make(map[string][]byte)
	data["pass"] = []byte("test123")

	s := NewSecret(data, "testsecret")
	assert.IsType(t, corev1.Secret{}, *s, "Secret must be of type v1.Secret")
	assert.Equal(t, "test123", string(s.Data["pass"]), "Secret must contain correct data")
}

func TestCleanup(t *testing.T) {
	err := os.Remove("secret.yaml")
	assert.NoError(t, err, "file must be removed.")
}
