package kube

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/kubernetes"
)

type Output interface {
	Write(p []byte) (n int, err error)
}

func GetSecretList(clientset *kubernetes.Clientset, namespace string) *corev1.SecretList {
	secrets, err := clientset.CoreV1().Secrets(namespace).List(metav1.ListOptions{})
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
