package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"

	"github.com/alecthomas/kingpin"
	"github.com/ghodss/yaml"
	"github.com/sebidude/kubecrypt/crypto"
	"github.com/sebidude/kubecrypt/kube"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	gitcommit    string
	appversion   string
	buildtime    string
	clientconfig *rest.Config
	clientset    *kubernetes.Clientset

	output       string
	namespace    string
	secretname   string
	keyname      string
	encrypt      bool
	tlsinfo      string
	tlssecret    string
	tlsnamespace string
	keyvalues    = make(map[string]string)
	labels       = make(map[string]string)
	remove       []string
	filename     = "-"
	outfile      = "-"
)

func main() {

	app := kingpin.New(os.Args[0], "encrypt decrypt data, convert yaml maps to kubernetes secrets and edit kubernetes secrets.")
	app.Flag("namespace", "Kubernetes namespace to be used.").Short('n').Envar("KUBECRYPT_NAMESPACE").StringVar(&namespace)
	app.Flag("in", "Input file to read from").Short('i').StringVar(&filename)
	app.Flag("out", "Output file to write the data to").Short('o').StringVar(&outfile)
	app.Flag("tls", "Namespace/Name of the tls secret to be used for crypto operations.").Default("kubecrypt/kubecrypt").Envar("KUBECRYPT_SECRET").Short('t').StringVar(&tlsinfo)

	get := app.Command("get", "Get the secret data.")
	get.Arg("secretname", "Name of the secret.").Required().StringVar(&secretname)
	get.Flag("key", "Name of the key in the secret").Default("").Short('k').StringVar(&keyname)

	app.Command("enc", "encrypt a secret")
	app.Command("dec", "decrypt")
	app.Command("version", "Print the version.")

	upd := app.Command("update", "Update the value of a secret for a given key")
	upd.Arg("secretname", "The name of the secret to be updated").Required().StringVar(&secretname)
	upd.Flag("keys", "the keys to be updated with values").Short('k').StringMapVar(&keyvalues)
	upd.Flag("rm", "Remove a key from a secret").Short('r').StringsVar(&remove)

	yml := app.Command("yaml", "Encrypt or Decrypt all values from yaml file")

	yml.Flag("key", "Key in the yaml to be processed").Required().Short('k').StringVar(&keyname)
	yml.Flag("ecrypt", "Encrypt the values").Short('e').BoolVar(&encrypt)

	convert := app.Command("convert", "convert encrypted yaml data to secret. If -e is passed create a yaml map with encrypted values of the data of the kubernetes secret.")
	convert.Arg("secretname", "Name for the converted secret.").Required().StringVar(&secretname)
	convert.Flag("encrypt", "Encrypt the values (default decrypt").Short('e').BoolVar(&encrypt)
	convert.Flag("key", "Key in the yaml to be used as data for the secret").Required().Short('k').StringVar(&keyname)
	convert.Flag("labels", "the labels to be applied to the new secret").Short('l').StringMapVar(&labels)

	app.Command("list", "List the secrets.")

	kubeconfig := os.Getenv("KUBECONFIG")
	if len(kubeconfig) < 1 {
		config, err := rest.InClusterConfig()
		if err != nil {
			panic(err.Error())
		}
		clientconfig = config
	} else {
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			panic(err.Error())
		}
		clientconfig = config
	}
	var err error
	clientset, err = kubernetes.NewForConfig(clientconfig)
	if err != nil {
		panic(err.Error())
	}

	operation := kingpin.MustParse(app.Parse(os.Args[1:]))

	tlsinfoparts := strings.Split(tlsinfo, "/")
	if len(tlsinfoparts) != 2 {
		checkError(fmt.Errorf("Malformed tlsinfo. Use -t namespace/secret."))
	}
	tlsnamespace = tlsinfoparts[0]
	tlssecret = tlsinfoparts[1]

	if namespace == "" {
		namespace, _, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(),
			&clientcmd.ConfigOverrides{},
		).Namespace()
		if err != nil {
			panic(err.Error())
		}
	}

	switch operation {
	case "list":
		listSecrets()
	case "get":
		getSecret()

	case "enc":
		inputbytes := readInputFromFile(filename)
		ciphertext := encryptData(inputbytes)
		encodedData := base64.RawURLEncoding.EncodeToString(ciphertext)
		writeOutputToFile([]byte(encodedData))

	case "dec":
		inputbytes := readInputFromFile(filename)
		if len(inputbytes) == 0 {
			fmt.Println("input is empty")
			return
		}
		decodedData, err := base64.RawURLEncoding.DecodeString(string(inputbytes))
		if err != nil {
			panic(err)
		}
		data := decryptData(decodedData)

		writeOutputToFile(data)
	case "yaml":
		inputbytes := readInputFromFile(filename)
		yamldata, _ := processYamlData(encrypt, inputbytes)
		writeOutputToFile(yamldata)
	case "convert":
		if encrypt {
			s, err := loadSecret(secretname, namespace)
			checkError(err)
			m := make(map[string]map[string]string)
			m[keyname] = make(map[string]string)

			for k, v := range s.Data {
				m[keyname][k] = string(v)
			}
			d, err := yaml.Marshal(m)
			checkError(err)
			e, _ := processYamlData(encrypt, d)
			writeOutputToFile(e)
			break
		}
		inputbytes := readInputFromFile(filename)
		_, datamap := processYamlData(encrypt, inputbytes)
		o := getOutputFile()
		s := kube.NewSecret(datamap, secretname)
		if len(labels) > 0 {
			s.ObjectMeta.Labels = labels
		}

		kube.ToManifest(s, o)

	case "update":
		s, err := loadSecret(secretname, namespace)
		checkError(err)
		if s == nil {
			fmt.Printf("Secret %q not found in namespace %q\n", secretname, namespace)
			break
		}
		if len(keyvalues) > 0 {
			updateSecret(s, keyvalues)
		}
		if len(remove) > 0 {
			updateSecret(s, remove)
		}

	case "version":
		fmt.Printf("kubecrypt\n version: %s\n commit: %s\n buildtime: %s\n", appversion, gitcommit, buildtime)
	}
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func readInputFromFile(filename string) []byte {
	var inputError error
	var input *os.File
	if filename == "-" {
		input = os.Stdin
	} else {
		input, inputError = os.Open(filename)
		checkError(inputError)
		defer input.Close()
	}

	data, err := ioutil.ReadAll(input)
	checkError(err)
	return data
}

func writeOutputToFile(data []byte) {
	if outfile == "-" {
		fmt.Print(string(data))
		return
	}

	// output the ciphertext
	output, err := os.Create(outfile)
	checkError(err)
	defer output.Close()
	output.Write(data)
}

func decryptData(data []byte) []byte {
	s, err := loadSecret(tlssecret, tlsnamespace)
	checkError(err)
	if _, ok := s.Data["tls.key"]; !ok {
		checkError(fmt.Errorf("No tls.key found in secret."))
	}

	keypem := s.Data["tls.key"]
	key, err := crypto.BytesToPrivateKey(keypem)
	checkError(err)

	cleartext, err := crypto.Decrypt(rand.Reader, key, data)
	checkError(err)
	return cleartext
}

func encryptData(data []byte) []byte {
	// load the cert from the secret
	var certpem []byte
	s, err := loadSecret(tlssecret, tlsnamespace)
	checkError(err)
	certpem = s.Data["tls.crt"]

	if len(certpem) == 0 {
		checkError(fmt.Errorf("Failed to load cert for encryption."))
	}

	rsaPublicKey := crypto.ReadPublicKeyFromCertPem(certpem)

	ciphertext := crypto.Encrypt(rand.Reader, rsaPublicKey, data)
	return ciphertext
}

func printOutput(s corev1.Secret, lookupkey string) {

	keys := reflect.ValueOf(s.Data).MapKeys()

	if len(lookupkey) > 0 {
		if _, ok := s.Data[lookupkey]; !ok {
			checkError(fmt.Errorf("The key %s does not exist.\n", lookupkey))
		}
		fmt.Printf("%s\n", lookupkey, s.Data[lookupkey])
		return

	} else {
		for _, v := range keys {
			key := v.String()
			fmt.Printf("%s: %s\n", key, s.Data[key])
		}
	}
}

func processYamlData(encryt bool, content []byte) ([]byte, map[string][]byte) {
	datamap := make(map[string][]byte)
	var yamlcontent map[string]interface{}
	err := yaml.Unmarshal(content, &yamlcontent)
	checkError(err)

	if _, ok := yamlcontent[keyname]; !ok {
		checkError(fmt.Errorf("key does not exist in yaml."))
	}
	if yamlmap, ok := yamlcontent[keyname].(map[string]interface{}); ok {

		for k, v := range yamlmap {

			switch v.(type) {
			case string:
				if encrypt {
					c := encryptData([]byte(v.(string)))
					yamlmap[k] = base64.RawURLEncoding.EncodeToString(c)
				} else {
					s, err := base64.RawURLEncoding.DecodeString(v.(string))
					checkError(err)
					c := decryptData(s)
					yamlmap[k] = string(c)
					datamap[k] = []byte(c)
				}

			default:
				checkError(fmt.Errorf("Only strings are allowed as values."))
			}
		}
		yamlcontent[keyname] = yamlmap
	}
	content, err = yaml.Marshal(yamlcontent)
	checkError(err)

	return content, datamap
}

func getOutputFile() *os.File {
	if outfile == "-" {
		return os.Stdout
	}

	// output the ciphertext
	output, err := os.Create(outfile)
	checkError(err)
	return output
}

func listSecrets() {
	secrets := kube.GetSecretList(clientset, namespace)
	for _, s := range secrets.Items {
		fmt.Println(s.Name)
	}
}

func getSecret() {
	secrets := kube.GetSecretList(clientset, namespace)
	for _, s := range secrets.Items {
		if s.Name == secretname && secretname != "all" {
			printOutput(s, keyname)
			return
		}

		if secretname == "all" {
			printOutput(s, "")
		}

	}
}

func loadSecret(secretname string, ns string) (*corev1.Secret, error) {
	secrets := kube.GetSecretList(clientset, ns)
	for _, s := range secrets.Items {
		if s.Name == secretname {
			return &s, nil
		}
	}
	return nil, fmt.Errorf("Secret %s not found in namespace %s", secretname, ns)
}

func updateSecret(s *corev1.Secret, items interface{}) {

	switch items.(type) {
	case []string:
		for _, v := range items.([]string) {
			if _, ok := s.Data[v]; ok {
				delete(s.Data, v)
			}
		}
	case map[string]string:
		for k, v := range items.(map[string]string) {
			s.Data[k] = []byte(v)
		}
	}

	_, err := clientset.CoreV1().Secrets(namespace).Update(s)
	checkError(err)
}
