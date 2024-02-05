PLUGIN_NAME="caddy-security"
PLUGIN_VERSION:=$(shell cat VERSION | head -1)
GIT_COMMIT:=$(shell git describe --dirty --always)
GIT_BRANCH:=$(shell git rev-parse --abbrev-ref HEAD -- | head -1)
LATEST_GIT_COMMIT:=$(shell git log --format="%H" -n 1 | head -1)
BUILD_USER:=$(shell whoami)
BUILD_DATE:=$(shell date +"%Y-%m-%d")
BUILD_DIR:=$(shell pwd)
CADDY_VERSION="v2.7.5"

all: info
	@mkdir -p bin/
	@rm -rf ./bin/authp
	@#rm -rf ../xcaddy-$(PLUGIN_NAME)/*
	@#mkdir -p ../xcaddy-$(PLUGIN_NAME) && cd ../xcaddy-$(PLUGIN_NAME) &&
	@#	xcaddy build $(CADDY_VERSION) --output ../$(PLUGIN_NAME)/bin/caddy
	@#	--with github.com/andrewsonpradeep/caddy-security@$(LATEST_GIT_COMMIT)=$(BUILD_DIR)
	@#	--with github.com/greenpau/caddy-trace@latest
	@#--with github.com/greenpau/go-authcrunch@v1.0.40=/home/greenpau/dev/go/src/github.com/greenpau/go-authcrunch
	@go build -v -o ./bin/authp cmd/authp/main.go
	@./bin/authp version
	@#bin/caddy run -config assets/config/Caddyfile
	@for f in `find ./assets -type f -name 'Caddyfile'`; do bin/authp fmt --overwrite $$f; done

.PHONY: info
info:
	@echo "DEBUG: Version: $(PLUGIN_VERSION), Branch: $(GIT_BRANCH), Revision: $(GIT_COMMIT)"
	@echo "DEBUG: Build on $(BUILD_DATE) by $(BUILD_USER)"

.PHONY: linter
linter:
	@echo "DEBUG: started $@"
	@#golint -set_exit_status ./...
	@echo "DEBUG: completed $@"

.PHONY: test
test: covdir linter
	@echo "DEBUG: started $@"
	@go test -v -coverprofile=.coverage/coverage.out ./...
	@echo "DEBUG: completed $@"

.PHONY: ctest
ctest: covdir linter
	@echo "DEBUG: started $@"
	@#time richgo test -v -coverprofile=.coverage/coverage.out ./...
	@time richgo test -v -coverprofile=.coverage/coverage.out ./*.go
	@echo "DEBUG: completed $@"

.PHONY: covdir
covdir:
	@echo "DEBUG: started $@"
	@mkdir -p .coverage
	@echo "DEBUG: completed $@"

.PHONY: bindir
bindir:
	@echo "DEBUG: started $@"
	@mkdir -p bin/
	@echo "DEBUG: completed $@"

.PHONY: coverage
coverage: covdir
	@echo "DEBUG: started $@"
	@go tool cover -html=.coverage/coverage.out -o .coverage/coverage.html
	@go test -covermode=count -coverprofile=.coverage/coverage.out ./...
	@go tool cover -func=.coverage/coverage.out | grep -v "100.0"
	@echo "DEBUG: completed $@"

.PHONY: clean
clean:
	@echo "DEBUG: started $@"
	@rm -rf .coverage/
	@rm -rf bin/
	@echo "DEBUG: completed $@"

.PHONY: qtest
qtest: covdir
	@echo "DEBUG: started $@"
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestApp ./*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestParseCaddyfileAppConfig ./*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestParseCaddyfileIdentity ./*.go
	@time richgo test -v -coverprofile=.coverage/coverage.out -run TestParseCaddyfileSingleSignOnProvider ./*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestParseCaddyfileCredentials ./*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestParseCaddyfileMessaging ./*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestParseCaddyfileIdentit* ./*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestParseCaddyfileAuthentication ./*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestParseCaddyfileAuthorization ./*.go
	@#go test -v -coverprofile=.coverage/coverage.out -run TestParseCaddyfile ./*.go
	@#go test -v -coverprofile=.coverage/coverage.out -run Test* ./pkg/services/...
	@go tool cover -html=.coverage/coverage.out -o .coverage/coverage.html
	@go tool cover -func=.coverage/coverage.out | grep -v "100.0"
	@echo "DEBUG: completed $@"

.PHONY: dep
dep:
	@echo "DEBUG: started $@"
	@go install golang.org/x/lint/golint@latest
	@go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
	@#go install github.com/goreleaser/goreleaser@latest
	@go install github.com/greenpau/versioned/cmd/versioned@latest
	@go install github.com/kyoh86/richgo@latest
	@echo "DEBUG: completed $@"

.PHONY: release
release:
	@echo "Making release"
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
	@echo "DEBUG: completed $@"

.PHONY: logo
logo:
	@mkdir -p assets/docs/images
	@gm convert -background black -font Bookman-Demi \
		-size 640x320 "xc:black" \
		-pointsize 72 \
		-draw "fill white gravity center text 0,0 'caddy\nsecurity'" \
		assets/docs/images/logo.png
	@echo "DEBUG: completed $@"

.PHONY: license
license:
	@for f in `find ./ -type f -name '*.go'`; do versioned -addlicense -copyright="Paul Greenberg greenpau@outlook.com" -year=2022 -filepath=$$f; done
	@assets/scripts/generate_downloads.sh
	@echo "DEBUG: completed $@"
