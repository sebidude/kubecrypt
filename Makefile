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
	@go get ./...

linux:
	@$(eval TARGET_OS := linux)
	@$(eval TARGET_LDFLAGS := $(LDFLAGS))
	@$(eval TARGET_ARCH := amd64)

macos:
	@$(eval TARGET_OS := darwin)
	@$(eval TARGET_LDFLAGS := $(LDFLAGS_MACOS))
	@$(eval TARGET_ARCH := arm64)

darwin: macos

install: build-$(TARGET_OS)
	cp build/$(TARGET_OS)/kubecrypt $$GOPATH/bin/
	
build: info dep
	@echo Building for $(TARGET_OS) 
	@mkdir -p build/$(TARGET_OS)
	@CGO_ENABLED=0 \
	GOOS=$(TARGET_OS) \
	GOARCH=$(TARGET_ARCH) \
	go build -o build/$(TARGET_OS)/$(APPNAME)-$(VERSIONTAG)-$(GITCOMMITHASH) -a -ldflags $(TARGET_LDFLAGS) $(APPSRC)
	@cp build/$(TARGET_OS)/$(APPNAME)-$(VERSIONTAG)-$(GITCOMMITHASH) build/$(TARGET_OS)/$(APPNAME)

image:
	docker build -t sebidude/kubecrypt:$(VERSIONTAG) .

publish:
	docker push sebidude/kubecrypt:$(VERSIONTAG) 

unittests:
	CGO_ENABLED=0 go test -v -count=1 -cover -coverprofile cover.out -p 1 $(addprefix $(PKG)/, $(TEST_PKG_LIST))

test: 
	@echo Running tests
	@rm -f secret.yaml
	@build/$(TARGET_OS)/kubecrypt init --local -t secret.yaml
	@echo -n "Encrypt yaml map: "	
	@build/$(TARGET_OS)/kubecrypt yaml --local -t secret.yaml -i unsafe.yaml -e -k data -o safe.yaml
	@grep foobary safe.yaml >/dev/null
	@if grep testme safe.yaml >/dev/null; then exit 1; fi
	@echo "ok"
	@echo -n "Decrypt yaml map: "
	@build/$(TARGET_OS)/kubecrypt yaml --local -t secret.yaml -i safe.yaml -k data | grep testme >/dev/null
	@echo "ok"
	@echo -n "Encrypt and decrypt text: "
	@echo 123 | build/$(TARGET_OS)/kubecrypt enc --local -t secret.yaml | build/$(TARGET_OS)/kubecrypt dec --local -t secret.yaml | grep 123 >/dev/null
	@echo "ok"
	@echo -n "Convert to secret: "
	@build/$(TARGET_OS)/kubecrypt convert --local -t secret.yaml mysecret -i safe.yaml -k data -o mysecret.yaml
	@grep dGVzdG1l mysecret.yaml >/dev/null
	@echo "ok"
	@echo -n "Convert from secret to safe yaml: "
	@build/$(TARGET_OS)/kubecrypt convert --local -t secret.yaml -e mysecret -f mysecret.yaml -k secret -o safemap.yaml
	@if ! grep password safemap.yaml >/dev/null; then exit 1; fi
	@echo "ok"
	@echo -n "Convert from secret stdin to safe yaml: "
	@cat  mysecret.yaml | build/$(TARGET_OS)/kubecrypt convert --local -t secret.yaml -e mysecret -k secret --from-file=- | grep password >/dev/null
	@echo "ok"
	@rm -f secret.yaml

clean-tests:
	rm safe.yaml mysecret.yaml safemap.yaml

pack: build
	@cd build/$(TARGET_OS) && tar cvfz $(APPNAME)-$(VERSIONTAG).tar.gz $(APPNAME)
