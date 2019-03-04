# kubecrypt

kubecrypt wants to help you to solve a bunch of problems when it comes to secrets.  
This project was inspired by [Bitnami Labs sealed-secrets](https://github.com/bitnami-labs/sealed-secrets) and the fact that I needed to solve some problems around storing secret data and use them in pipelining.  

Contributions are welcome. The code is working and tested manually. As this is a kubernetes client, I recommend to build the tool and deploy it with some docker image if you need to use it in your pipelines.  

It can do the following things:
* list secrets for a namespace
* print values from a secret
* encrypt /decrypt data using a tls secret from the cluster
* encrypt / decrypt all values for a map in a yaml file
* convert a yaml map with encrypted values to a plain kubernetes secret
* remove keys from a secret
* update keys of a secret

## Install

```
go get github.com/sebidude/kubecrypt
go install github.com/sebidude/kubecrypt/cmd/kubecrypt
```



## Usage

You can always use the --help flag. Beside handling your secrets you can also use kubecrypt to quickly encrypt some text and share it with your co-workers via chat in a secure way.  
Generate a key and a self-signed cert for kubecrypt
```
openssl genrsa -nodes -out tls.key 4096
openssl req -key tls.key -x509 -days 365 -out tls.crt -subj "/C=XX/ST=Coruscant/L=Temple/O=Force/OU=Temple Admins/CN=Jedis"
```

Add the cert and key to the cluster
```
kubectl create namespace kubecrypt
kubectl create secret tls kubecrypt -n kubecrypt --cert=tls.crt --key=tls.key
```

Store the key in a secret place!

### Encrypt and Decrypt data

You can encrypt data using a tls secret from the cluster. The encrypted output is always base64 raw url encoded.

```
# encrypt to stdout
echo This is some data | kubecrypt enc

# encrypt to a file
echo This is some data | kubecrypt enc -o encrypted.txt
```

Decrypt data this way
```
# decrypt from file
kubecrypt dec -i encrypted.txt

# decrypt from stdin
cat encrypted.txt | kubecrypt dec

# or
echo This is some data | kubecrypt enc | kubecrypt dec
```

---
### Encrypt and decrypt values from a yaml map

If you have an input file in yaml format, you can encrypt or decrypt all members of a map with a given key. Note the this will only work with string values.

Example yaml file unsafe.yaml:

```yaml
data:
  password: f0oB4r
  key: mykey
```

Now encrypt all values for the keys in the map `data`:

```
# from stdin
cat unsafe.yaml | kubecrypt yaml -e -k data

# from file
kubecrypt yaml -e -k data -i unsafe.yaml

# from file to output file
kubecrypt yaml -e -k data -i unsafe.yaml -o safe.yaml
```

If you skip the `-e` flag, the input will be decrypted

```
kubecrypt yaml -i safe.yaml -k data
```

---
### Convert the values from a encrypted yaml map to a kubernetes secret

```
kubecrypt convert mysecret -i safe.yaml -k data -o mysecret.yaml
```

---
### Update and remove keys from kubernetes secrets in cluster

Update a key of an existing secret, if the key doesn't exist it will be added to the secret

```
kubecrypt update -k foo=bar -k token=updatedToken mysecret
```

Remove a key from secret
```
kubecrypt update -r foo mysecret
```