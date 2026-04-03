PLUGIN_NAME="caddy-security"
PLUGIN_VERSION:=$(shell cat VERSION | head -1)
GIT_COMMIT:=$(shell git describe --dirty --always)
GIT_BRANCH:=$(shell git rev-parse --abbrev-ref HEAD -- | head -1)
LATEST_GIT_COMMIT:=$(shell git log --format="%H" -n 1 | head -1)
BUILD_USER:=$(shell whoami)
BUILD_DATE:=$(shell date +"%Y-%m-%d")
BUILD_DIR:=$(shell pwd)
CADDY_VERSION="v2.11.2"

VERBOSE:=-v
ifdef TEST
	TEST:="-run ${TEST}"
endif
TEST_DIR:="./..."

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
		--with github.com/greenpau/caddy-security-secrets-static-secrets-manager@latest \
		--with github.com/greenpau/caddy-trace@latest \
		--with github.com/greenpau/go-authcrunch@v1.1.38=/Users/greenpau/dev/src/github.com/greenpau/go-authcrunch
	@./bin/authcrunch version
	@echo "$@: complete"

.PHONY: linter
linter:
	@echo "$@: started"
	@#golint -set_exit_status ./...
	@echo "$@: complete"

.PHONY: fmtcfg
fmtcfg:
	@echo "$@: started"
	@for f in `find ./testdata/caddyfile_adapt/ -type f -name '*.Caddyfile'`; do bin/authcrunch fmt --overwrite $$f; done
	@for f in `find ./assets/config/ -type f -name '*Caddyfile'`; do bin/authcrunch fmt --overwrite $$f; done
	@echo "$@: complete"

.PHONY: install-test-tools
install-test-tools:
	@echo "$@: started"
	@richgo version || go install github.com/kyoh86/richgo@latest
	@tparse -v || go install github.com/mfridman/tparse@latest
	@go-test-report version || go install github.com/vakenbolt/go-test-report@latest
	@echo "$@: complete"

.PHONY: run-tests
run-tests:
	@echo "$@: started"
	@go test -json $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out $(TEST_DIR) | tee .coverage/test_output.jsonl
	@echo "$@: complete"

QUICK_TEST_DIR="./..."
QUICK_TEST_PATTERN_RUN="-run"
#QUICK_TEST_PATTERN="Test(CaddyfileAdaptAuthenticationToJSON|ResolveRuntimeAppConfig)"
#QUICK_TEST_PATTERN="Test(ParseCaddyfileIdentity)"
#QUICK_TEST_PATTERN="Test(ParseCaddyfileAuthentication)"
#QUICK_TEST_PATTERN="Test(ParseCaddyfileAuthenticationMisc)"
QUICK_TEST_PATTERN="Test(ParseCaddyfileAuthorization)"
.PHONY: run-quick-tests
run-quick-tests:
	@echo "$@: started"
	@go test -json $(VERBOSE) -coverprofile=.coverage/coverage.out $(QUICK_TEST_PATTERN_RUN) $(QUICK_TEST_PATTERN) $(QUICK_TEST_DIR) | tee .coverage/test_output.jsonl
	@echo "$@: complete"

.PHONY: run-reports
run-reports:
	@echo "$@: started"
	@cat .coverage/test_output.jsonl | go-test-report -o .coverage/test_output.html
	@go tool cover -html=.coverage/coverage.out -o .coverage/coverage.html
	@echo "$@: complete"


.PHONY: test
test: covdir linter install-test-tools run-tests run-reports
	@if grep -q '"Action":"fail"' .coverage/test_output.jsonl; then \
		echo "ERROR: Go tests failed! See .coverage/test_output.jsonl for details."; \
		exit 1; \
	fi
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
qtest: covdir install-test-tools run-quick-tests run-reports
	@if grep -q '"Action":"fail"' .coverage/test_output.jsonl; then \
		echo "ERROR: Go tests failed! See .coverage/test_output.jsonl for details."; \
		exit 1; \
	fi
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


.PHONY: sync
sync:
	@echo "DEBUG: started $@"
	@assets/scripts/update_doc_refs.sh

.PHONY: release-git-check
release-git-check:
	@echo "DEBUG: started $@"
	@go mod tidy;
	@go mod verify;
	@if [ $(GIT_BRANCH) != "main" ]; then echo "cannot release to non-main branch $(GIT_BRANCH)" && false; fi
	@git diff-index --quiet HEAD -- || ( echo "git directory is dirty, commit changes first" && false )
	@echo "DEBUG: completed $@"

.PHONY: release-update-version
release-update-version:
	@echo "DEBUG: started $@"
	@versioned -patch
	@assets/scripts/generate_downloads.sh
	@git add VERSION README.md CONTRIBUTING.md Makefile

.PHONY: release-git-commit
release-git-commit:
	@echo "DEBUG: started $@"
	@git commit -m "released v`cat VERSION | head -1`"
	@git tag -a v`cat VERSION | head -1` -m "v`cat VERSION | head -1`"
	@git push
	@git push --tags
	@echo "If necessary, run the following commands:"
	@echo "  git push --delete origin v$(PLUGIN_VERSION)"
	@echo "  git tag --delete v$(PLUGIN_VERSION)"
	@echo "  go mod edit -retract v$(PLUGIN_VERSION)"
	@echo "DEBUG: completed $@"

.PHONY: release
release: release-git-check build release-update-version release-git-commit
	@echo "DEBUG: completed $@"

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

.PHONY: upgrade
upgrade:
	@echo "$@: started"
	@go get -u ./...
	@go mod tidy
	@echo "$@: complete"

.PHONY: license
license:
	@echo "$@: started"
	@for f in `find ./ -type f -name '*.go'`; do versioned -addlicense -copyright="Paul Greenberg greenpau@outlook.com" -year=2022 -filepath=$$f; done
	@assets/scripts/generate_downloads.sh
	@echo "$@: complete"
