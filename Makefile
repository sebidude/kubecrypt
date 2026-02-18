APPNAME := kubecrypt
APPSRC := ./cmd/$(APPNAME)

PKG := github.com/sebidude/kubecrypt
TEST_PKG_LIST := kube crypto

GITCOMMITHASH := $(shell git log --max-count=1 --pretty="format:%h" HEAD)
GITCOMMIT := -X main.gitcommit=$(GITCOMMITHASH)

VERSIONTAG := $(shell git describe --tags --abbrev=0)
VERSION := -X main.appversion=$(VERSIONTAG)

BUILDTIMEVALUE := $(shell date +%Y-%m-%dT%H:%M:%S%z)
BUILDTIME := -X main.buildtime=$(BUILDTIMEVALUE)

LDFLAGS := '-extldflags "-static" -d -s -w $(GITCOMMIT) $(VERSION) $(BUILDTIME)'
LDFLAGS_MACOS := '-extldflags "-static" -s -w $(GITCOMMIT) $(VERSION) $(BUILDTIME)'
LDFLAGS_WINDOWS := '-extldflags "-static" -s -w $(GITCOMMIT) $(VERSION) $(BUILDTIME)'

KUBEAPIVERSION := 1.35

clean: clean-tests
	rm -rf build

info: 
	@echo - appname:   $(APPNAME)
	@echo - verison:   $(VERSIONTAG)
	@echo - commit:    $(GITCOMMITHASH)
	@echo - buildtime: $(BUILDTIMEVALUE) 

dep:
	@go get -d ./...

install: build-linux
	cp build/linux/kubecrypt $$GOPATH/bin/
	
build-linux: info dep
	@echo Building for linux
	@mkdir -p build/linux
	@CGO_ENABLED=0 \
	GOOS=linux \
	go build -o build/linux/$(APPNAME)-$(VERSIONTAG)-$(GITCOMMITHASH) -a -ldflags $(LDFLAGS) $(APPSRC)
	@cp build/linux/$(APPNAME)-$(VERSIONTAG)-$(GITCOMMITHASH) build/linux/$(APPNAME)

build-macos: info dep
	@echo Building for macos 
	@mkdir -p build/macos
	@CGO_ENABLED=0 \
	GOOS=darwin \
	GOARCH=arm64 \
	go build -o build/macos/$(APPNAME)-$(VERSIONTAG)-$(GITCOMMITHASH) -a -ldflags $(LDFLAGS_MACOS) $(APPSRC)
	@cp build/macos/$(APPNAME)-$(VERSIONTAG)-$(GITCOMMITHASH) build/macos/$(APPNAME)


image:
	docker build -t sebidude/kubecrypt:$(VERSIONTAG) .

publish:
	docker push sebidude/kubecrypt:$(VERSIONTAG) 

unittests:
	CGO_ENABLED=0 go test -v -count=1 -cover -coverprofile cover.out -p 1 $(addprefix $(PKG)/, $(TEST_PKG_LIST))

test: 
	@echo Running tests
	@rm -f secret.yaml
	@build/macos/kubecrypt init --local -t secret.yaml
	@echo -n "Encrypt yaml map: "	
	@build/macos/kubecrypt yaml --local -t secret.yaml -i unsafe.yaml -e -k data -o safe.yaml
	@grep foobary safe.yaml >/dev/null
	@if grep testme safe.yaml >/dev/null; then exit 1; fi
	@echo "ok"
	@echo -n "Decrypt yaml map: "
	@build/macos/kubecrypt yaml --local -t secret.yaml -i safe.yaml -k data | grep testme >/dev/null
	@echo "ok"
	@echo -n "Encrypt and decrypt text: "
	@echo 123 | build/macos/kubecrypt enc --local -t secret.yaml | build/macos/kubecrypt dec --local -t secret.yaml | grep 123 >/dev/null
	@echo "ok"
	@echo -n "Convert to secret: "
	@build/macos/kubecrypt convert --local -t secret.yaml mysecret -i safe.yaml -k data -o mysecret.yaml
	@grep dGVzdG1l mysecret.yaml >/dev/null
	@echo "ok"
	@echo -n "Convert from secret to safe yaml: "
	@build/macos/kubecrypt convert --local -t secret.yaml -e mysecret -f mysecret.yaml -k secret -o safemap.yaml
	@if ! grep password safemap.yaml >/dev/null; then exit 1; fi
	@echo "ok"
	@echo -n "Convert from secret stdin to safe yaml: "
	@cat  mysecret.yaml | build/macos/kubecrypt convert --local -t secret.yaml -e mysecret -k secret --from-file=- | grep password >/dev/null
	@echo "ok"
	@rm -f secret.yaml

clean-tests:
	rm safe.yaml mysecret.yaml safemap.yaml

pack: build-linux
	@cd build/linux && tar cvfz $(APPNAME)-$(VERSIONTAG).tar.gz $(APPNAME)
