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

	output     string
	namespace  string
	secretname string
	keyname    string
	encrypt    bool
	tlssecret  string
	keyvalues  = make(map[string]string)
	remove     []string
	filename   = "-"
	outfile    = "-"
)

func main() {

	app := kingpin.New(os.Args[0], "encrypt decrypt data, convert yaml maps to kubernetes secrets and edit kubernetes secrets.")
	app.Flag("namespace", "Kubernetes namespace to be used.").Default("kubecrypt").Short('n').Envar("KUBECRYPT_NAMESPACE").StringVar(&namespace)
	app.Flag("in", "Input file to read from").Short('i').StringVar(&filename)
	app.Flag("out", "Output file to write the data to").Short('o').StringVar(&outfile)
	app.Flag("tls", "Name of the tls secret to be used for crypto operations.").Default("kubecrypt").Envar("KUBECRYPT_SECRET").Short('t').StringVar(&tlssecret)

	get := app.Command("get", "Get the secret data.")
	get.Arg("secretname", "Name of the secret.").Required().StringVar(&secretname)
	get.Flag("key", "Name of the key in the secret").Default("").Short('k').StringVar(&keyname)
	get.Flag("format", "Output format: simple (no keys), yaml , env (oneliner of shell vars), export (for sourcing the output), gradle (for use with gradle)").Default("yaml").Short('f').HintOptions("simple", "env", "yaml", "export").StringVar(&output)

	app.Command("enc", "encrypt a secret")
	app.Command("dec", "decrypt")

	upd := app.Command("update", "Update the value of a secret for a given key")
	upd.Arg("secretname", "The name of the secret to be updated").Required().StringVar(&secretname)
	upd.Flag("keys", "the keys to be updated with values").Short('k').StringMapVar(&keyvalues)
	upd.Flag("rm", "Remove a key from a secret").Short('r').StringsVar(&remove)

	yml := app.Command("yaml", "Encrypt or Decrypt all values from yaml file")

	yml.Flag("key", "Key in the yaml to be processed").Required().Short('k').StringVar(&keyname)
	yml.Flag("ecrypt", "Encrypt the values").Short('e').BoolVar(&encrypt)

	convert := app.Command("convert", "convert yaml data to secret")
	convert.Arg("secretname", "Name for the converted secret.").Required().StringVar(&secretname)
	convert.Flag("ecrypt", "Encrypt the values (default decrypt").Short('e').BoolVar(&encrypt)
	convert.Flag("key", "Key in the yaml to be used as data for the secret").Default("secrets").Short('k').StringVar(&keyname)

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

	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
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
		inputbytes := readInputFromFile(filename)
		//fmt.Println(string(inputbytes))
		_, datamap := processYamlData(encrypt, inputbytes)
		o := getOutputFile()
		s := kube.NewSecret(datamap, secretname)
		kube.ToManifest(s, o)

	case "update":
		s := loadSecret(secretname)
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

	}
}

func readInputFromFile(filename string) []byte {
	var inputError error
	var input *os.File
	if filename == "-" {
		input = os.Stdin
	} else {
		input, inputError = os.Open(filename)
		if inputError != nil {
			panic(inputError)
		}
		defer input.Close()
	}

	data, err := ioutil.ReadAll(input)
	if err != nil {
		panic(err)
	}
	return data
}

func writeOutputToFile(data []byte) {
	if outfile == "-" {
		fmt.Print(string(data))
		return
	}

	// output the ciphertext
	output, err := os.Create(outfile)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer output.Close()
	output.Write(data)
}

func decryptData(data []byte) []byte {
	s := loadSecret(tlssecret)
	if _, ok := s.Data["tls.key"]; !ok {
		panic("No tls.key found in secret.")
	}

	keypem := s.Data["tls.key"]
	key := crypto.BytesToPrivateKey(keypem)

	cleartext := crypto.Decrypt(rand.Reader, key, data)
	return cleartext
}

func encryptData(data []byte) []byte {
	// load the cert from the secret
	var certpem []byte
	s := loadSecret(tlssecret)
	certpem = s.Data["tls.crt"]

	if len(certpem) == 0 {
		panic("Failed to load cert for encryption.")
	}

	rsaPublicKey := crypto.ReadPublicKeyFromCertPem(certpem)

	ciphertext := crypto.Encrypt(rand.Reader, rsaPublicKey, data)
	return ciphertext
}

func printOutput(s corev1.Secret, lookupkey string) {

	keys := reflect.ValueOf(s.Data).MapKeys()

	if len(lookupkey) > 0 {
		if _, ok := s.Data[lookupkey]; !ok {
			fmt.Printf("The key %s does not exist.\n", lookupkey)
			return
		}
		if output == "yaml" {
			fmt.Printf("%s: %s\n", lookupkey, s.Data[lookupkey])
			return
		}
	} else {
		for _, v := range keys {
			key := v.String()
			data := fmt.Sprintf("%q", s.Data[key])
			if output == "yaml" {
				fmt.Printf("%s: %s\n", key, s.Data[key])
			} else if output == "env" {
				fmt.Printf("%s=%q ", strings.Replace(strings.ToUpper(key), ".", "_", -1), data)
			} else if output == "export" {
				fmt.Printf("export %s=%q\n", strings.Replace(strings.ToUpper(key), ".", "_", -1), data)
			} else if output == "gradle" {
				fmt.Printf("-P%s=%s ", key, s.Data[key])
			} else {
				fmt.Printf("%s\n", data)
			}
		}
	}
}

func processYamlData(encryt bool, content []byte) ([]byte, map[string][]byte) {
	datamap := make(map[string][]byte)
	var yamlcontent map[string]interface{}
	err := yaml.Unmarshal(content, &yamlcontent)
	if err != nil {
		panic(err)
	}

	if _, ok := yamlcontent[keyname]; !ok {
		panic("key does not exist in yaml.")
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
					if err != nil {
						panic(err)
					}
					c := decryptData(s)
					yamlmap[k] = string(c)
					datamap[k] = []byte(c)
				}

			default:
				panic("Only strings are allowed as values.")
			}
		}
		yamlcontent[keyname] = yamlmap
	}
	content, err = yaml.Marshal(yamlcontent)
	if err != nil {
		panic(err)
	}

	return content, datamap
}

func getOutputFile() *os.File {
	if outfile == "-" {
		return os.Stdout
	}

	// output the ciphertext
	output, err := os.Create(outfile)
	if err != nil {
		panic(err)
	}
	return output
}

func convertToSecret(data map[string][]byte) {

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

func loadSecret(secretname string) *corev1.Secret {
	secrets := kube.GetSecretList(clientset, namespace)
	for _, s := range secrets.Items {
		if s.Name == secretname {
			return &s
		}
	}
	return nil
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
	if err != nil {
		panic(err)
	}
}
