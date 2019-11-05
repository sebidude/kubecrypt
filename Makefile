APPNAME := kubecrypt
APPSRC := ./cmd/$(APPNAME)

GITCOMMITHASH := $(shell git log --max-count=1 --pretty="format:%h" HEAD)
GITCOMMIT := -X main.gitcommit=$(GITCOMMITHASH)

VERSIONTAG := $(shell git describe --tags --abbrev=0)
VERSION := -X main.appversion=$(VERSIONTAG)

BUILDTIMEVALUE := $(shell date +%Y-%m-%dT%H:%M:%S%z)
BUILDTIME := -X main.buildtime=$(BUILDTIMEVALUE)

LDFLAGS := '-extldflags "-static" -d -s -w $(GITCOMMIT) $(VERSION) $(BUILDTIME)'
LDFLAGS_WINDOWS := '-extldflags "-static" -s -w $(GITCOMMIT) $(VERSION) $(BUILDTIME)'

KUBEAPIVERSION := 1.15

clean: clean-tests
	rm -rf build

info: 
	@echo - appname:   $(APPNAME)
	@echo - verison:   $(VERSIONTAG)
	@echo - commit:    $(GITCOMMITHASH)
	@echo - buildtime: $(BUILDTIMEVALUE) 

dep:
	@go get -v -d ./...

install: build-linux
	cp build/linux/kubecrypt $$GOPATH/bin/
	
build-linux: info dep
	@echo Building for linux
	@mkdir -p build/linux
	@CGO_ENABLED=0 \
	GOOS=linux \
	go build -o build/linux/$(APPNAME)-$(VERSIONTAG)-$(GITCOMMITHASH) -a -ldflags $(LDFLAGS) $(APPSRC)
	@cp build/linux/$(APPNAME)-$(VERSIONTAG)-$(GITCOMMITHASH) build/linux/$(APPNAME)

image:
	docker build -t sebidude/kubecrypt:$(VERSIONTAG) .

publish:
	docker push sebidude/kubecrypt:$(VERSIONTAG) 

test: 
	@echo Running tests
	@echo -n "Encrypt yaml map: "	
	@build/linux/kubecrypt yaml -i unsafe.yaml -e -k data -o safe.yaml
	@grep foobary safe.yaml >/dev/null
	@if grep testme safe.yaml >/dev/null; then exit 1; fi
	@echo "ok"
	@echo -n "Decrypt yaml map: "
	@build/linux/kubecrypt yaml -i safe.yaml -k data | grep testme >/dev/null
	@echo "ok"
	@echo -n "Encrypt and decrypt text: "
	@echo 123 | build/linux/kubecrypt enc | build/linux/kubecrypt dec | grep 123 >/dev/null
	@echo "ok"
	@echo -n "Convert to secret: "
	@build/linux/kubecrypt convert mysecret -i safe.yaml -k data -o mysecret.yaml
	@grep dGVzdG1l mysecret.yaml >/dev/null
	@echo "ok"
	@echo -n "Apply secret to cluster: "
	@kubectl apply -f mysecret.yaml -n kubecrypt
	@echo -n "Load a secret from the cluster: "
	@build/linux/kubecrypt -n kubecrypt get mysecret | grep testme >/dev/null
	@echo "ok"

clean-tests:
	rm safe.yaml mysecret.yaml
