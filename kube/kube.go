package kube

import (
	"bytes"
	"context"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
)

type Output interface {
	Write(p []byte) (n int, err error)
}

func GetSecretList(clientset *kubernetes.Clientset, namespace string) *corev1.SecretList {
	ctx := context.Background()
	defer ctx.Done()
	secrets, err := clientset.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	return secrets
}

func ToManifest(o interface{}, out Output) {
	e := json.NewYAMLSerializer(json.DefaultMetaFactory, nil, nil)
	obj := o.(runtime.Object)
	err := e.Encode(obj, out)
	if err != nil {
		panic(err)
	}

}

func SecretsFromManifestBytes(m []byte) (*corev1.Secret, error) {
	s := new(corev1.Secret)
	dec := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(m), len(m))
	if err := dec.Decode(&s); err != nil {
		return nil, err
	}
	return s, nil
}

func InitKubecryptSecret(clientset *kubernetes.Clientset, tlskey, tlscert []byte, namespace string, secretname string, runlocal bool) error {
	ctx := context.Background()
	defer ctx.Done()

	data := make(map[string][]byte)
	data["tls.key"] = tlskey
	data["tls.crt"] = tlscert

	s := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		Type: corev1.SecretTypeTLS,
		ObjectMeta: metav1.ObjectMeta{
			Name: secretname,
		},
		Data: data,
	}

	if runlocal {
		_, err := os.Stat(secretname)
		if err != nil && !os.IsNotExist(err) {
			return err
		} else if err == nil {
			return fmt.Errorf("File %s already exist. Will not override.", secretname)
		}

		out, err := os.Create(secretname)
		if err != nil {
			return err
		}
		ToManifest(s, out)
		return nil
	}
	_, err := clientset.CoreV1().Secrets(namespace).Create(ctx, s, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func NewSecret(data map[string][]byte, name string) *corev1.Secret {
	s := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		Type: corev1.SecretTypeOpaque,
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Data: data,
	}
	return s
}
