PLUGIN_NAME="caddy-security"
PLUGIN_VERSION:=$(shell cat VERSION | head -1)
GIT_COMMIT:=$(shell git describe --dirty --always)
GIT_BRANCH:=$(shell git rev-parse --abbrev-ref HEAD -- | head -1)
LATEST_GIT_COMMIT:=$(shell git log --format="%H" -n 1 | head -1)
BUILD_USER:=$(shell whoami)
BUILD_DATE:=$(shell date +"%Y-%m-%d")
BUILD_DIR:=$(shell pwd)
CADDY_VERSION="v2.7.5"

all: info build
	@echo "$@: complete"

.PHONY: info
info:
	@echo "DEBUG: Version: $(PLUGIN_VERSION), Branch: $(GIT_BRANCH), Revision: $(GIT_COMMIT)"
	@echo "DEBUG: Build on $(BUILD_DATE) by $(BUILD_USER)"

.PHONY: build
build:
	@mkdir -p bin/
	@rm -rf ./bin/authcrunch
	@go build -v -o ./bin/authcrunch cmd/authcrunch/main.go;
	@./bin/authcrunch version
	@for f in `find ./assets -type f -name 'Caddyfile'`; do bin/authcrunch fmt --overwrite $$f; done
	@echo "$@: complete"

.PHONY: devbuild
devbuild:
	@mkdir -p bin/
	@rm -rf ./bin/authcrunch
	@rm -rf ../xcaddy-$(PLUGIN_NAME)/*
	@mkdir -p ../xcaddy-$(PLUGIN_NAME) && cd ../xcaddy-$(PLUGIN_NAME) && \
		xcaddy build $(CADDY_VERSION) --output ../$(PLUGIN_NAME)/bin/authcrunch \
		--with github.com/greenpau/caddy-security@$(LATEST_GIT_COMMIT)=$(BUILD_DIR) \
		--with github.com/greenpau/caddy-trace@latest \
		--with github.com/greenpau/go-authcrunch@v1.1.4=/home/greenpau/dev/go/src/github.com/greenpau/go-authcrunch
	@go build -v -o ./bin/authcrunch cmd/authcrunch/main.go;
	@./bin/authcrunch version
	@echo "$@: complete"

.PHONY: linter
linter:
	@echo "$@: started"
	@#golint -set_exit_status ./...
	@echo "$@: complete"

.PHONY: test
test: covdir linter
	@echo "$@: started"
	@echo "DEBUG: started $@"
	@go test -v -coverprofile=.coverage/coverage.out ./...
	@echo "$@: complete"

.PHONY: ctest
ctest: covdir linter
	@echo "$@: started"
	@echo "DEBUG: started $@"
	@#time richgo test -v -coverprofile=.coverage/coverage.out ./...
	@time richgo test -v -coverprofile=.coverage/coverage.out ./*.go
	@echo "$@: complete"

.PHONY: covdir
covdir:
	@echo "$@: started"
	@mkdir -p .coverage
	@echo "$@: complete"

.PHONY: bindir
bindir:
	@echo "$@: started"
	@mkdir -p bin/
	@echo "$@: complete"

.PHONY: coverage
coverage: covdir
	@echo "$@: started"
	@go tool cover -html=.coverage/coverage.out -o .coverage/coverage.html
	@go test -covermode=count -coverprofile=.coverage/coverage.out ./...
	@go tool cover -func=.coverage/coverage.out | grep -v "100.0"
	@echo "$@: complete"

.PHONY: clean
clean:
	@echo "$@: started"
	@rm -rf .coverage/
	@rm -rf bin/
	@echo "$@: complete"

.PHONY: qtest
qtest: covdir
	@echo "$@: started"
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestApp ./*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestParseCaddyfileAppConfig ./*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestParseCaddyfileIdentity ./*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestParseCaddyfileSingleSignOnProvider ./*.go
	@time richgo test -v -coverprofile=.coverage/coverage.out -run TestParseCaddyfileAuthenticationMisc ./*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestParseCaddyfileCredentials ./*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestParseCaddyfileMessaging ./*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestParseCaddyfileIdentit* ./*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestParseCaddyfileAuthentication ./*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestParseCaddyfileAuthorization ./*.go
	@#go test -v -coverprofile=.coverage/coverage.out -run TestParseCaddyfile ./*.go
	@#go test -v -coverprofile=.coverage/coverage.out -run Test* ./pkg/services/...
	@go tool cover -html=.coverage/coverage.out -o .coverage/coverage.html
	@go tool cover -func=.coverage/coverage.out | grep -v "100.0"
	@echo "$@: complete"

.PHONY: dep
dep:
	@echo "$@: started"
	@go install golang.org/x/lint/golint@latest
	@go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
	@#go install github.com/goreleaser/goreleaser@latest
	@go install github.com/greenpau/versioned/cmd/versioned@latest
	@go install github.com/kyoh86/richgo@latest
	@echo "$@: complete"

.PHONY: release
release:
	@echo "$@: started"
	@go mod tidy;
	@go mod verify;
	@if [ $(GIT_BRANCH) != "main" ]; then echo "cannot release to non-main branch $(GIT_BRANCH)" && false; fi
	@git diff-index --quiet HEAD -- || ( echo "git directory is dirty, commit changes first" && false )
	@versioned -patch
	@echo "Patched version"
	@assets/scripts/generate_downloads.sh
	@git add VERSION README.md
	@git commit -m "released v`cat VERSION | head -1`"
	@git tag -a v`cat VERSION | head -1` -m "v`cat VERSION | head -1`"
	@git push
	@git push --tags
	@@echo "If necessary, run the following commands:"
	@echo "  git push --delete origin v$(PLUGIN_VERSION)"
	@echo "  git tag --delete v$(PLUGIN_VERSION)"
	@echo "$@: complete"

.PHONY: logo
logo:
	@echo "$@: started"
	@mkdir -p assets/docs/images
	@gm convert -background black -font Bookman-Demi \
		-size 640x320 "xc:black" \
		-pointsize 72 \
		-draw "fill white gravity center text 0,0 'caddy\nsecurity'" \
		assets/docs/images/logo.png
	@echo "$@: complete"

.PHONY: license
license:
	@echo "$@: started"
	@for f in `find ./ -type f -name '*.go'`; do versioned -addlicense -copyright="Paul Greenberg greenpau@outlook.com" -year=2022 -filepath=$$f; done
	@assets/scripts/generate_downloads.sh
	@echo "$@: complete"
