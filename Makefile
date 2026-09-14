SHELL := /bin/bash
.DEFAULT_GOAL := all

PLUGIN_NAME="caddy-security"
PLUGIN_VERSION:=$(shell cat VERSION | head -1)
GIT_COMMIT:=$(shell git describe --dirty --always)
GIT_BRANCH:=$(shell git rev-parse --abbrev-ref HEAD -- | head -1)
LATEST_GIT_COMMIT:=$(shell git log --format="%H" -n 1 | head -1)
BUILD_USER:=$(shell whoami)
BUILD_DATE:=$(shell date +"%Y-%m-%d")
BUILD_DIR:=$(shell pwd)
CADDY_VERSION="v2.11.4"

PYTHON ?= python3
TEST ?= .
TEST_DIR ?= ./...
TEST_TIMEOUT ?= 20m
QUICK_TEST_DIR ?= .
COVERAGE_DIR ?= .coverage
MINIMUM_COVERAGE ?= 1
export TEST TEST_DIR TEST_TIMEOUT QUICK_TEST_DIR COVERAGE_DIR MINIMUM_COVERAGE
export PLUGIN_VERSION GIT_COMMIT GIT_BRANCH BUILD_USER BUILD_DATE
export PYTHONDONTWRITEBYTECODE := 1

all: info build
	@echo "$@: complete"

.PHONY: info
info:
	@echo "DEBUG: Version: $$PLUGIN_VERSION, Branch: $$GIT_BRANCH, Revision: $$GIT_COMMIT"
	@echo "DEBUG: Build on $$BUILD_DATE by $$BUILD_USER"

.PHONY: build
build: version-check
	@mkdir -p bin/
	@go build -mod=readonly -trimpath -v -o ./bin/authcrunch ./cmd/authcrunch
	@./bin/authcrunch version
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
		--with github.com/greenpau/go-authcrunch@v1.1.41=/Users/greenpau/dev/src/github.com/greenpau/go-authcrunch
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
	@go tool tested version

.PHONY: run-tests
run-tests:
	@go tool tested run --output-dir "$$COVERAGE_DIR" \
		--title "Caddy Security Go tests" --minimum-coverage "$$MINIMUM_COVERAGE" \
		-- -mod=readonly -race -count=1 -timeout "$$TEST_TIMEOUT" -v -run "$$TEST" $$TEST_DIR

.PHONY: run-quick-tests
run-quick-tests:
	@$(MAKE) run-tests TEST_DIR="$$QUICK_TEST_DIR" COVERAGE_DIR="$$COVERAGE_DIR/quick"

.PHONY: run-reports
run-reports:
	@go tool tested report --output-dir "$$COVERAGE_DIR" --title "Caddy Security Go tests"


.PHONY: test
test: run-tests

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
coverage: run-reports

.PHONY: clean
clean:
	@echo "$@: started"
	@rm -rf .coverage/
	@rm -rf bin/
	@echo "$@: complete"

.PHONY: qtest
qtest: run-quick-tests

.PHONY: dep
dep:
	@go mod download
	@go mod verify
	@$(MAKE) install-test-tools

.PHONY: test-automation ci-check version-check artifact-id
test-automation:
	@$(PYTHON) -m unittest discover -s assets/scripts/tests -p '*_test.py' -v

# Recursive invocations serialize gates even when the caller uses make -j.
ci-check:
	@$(MAKE) version-check
	@$(MAKE) test-automation
	@$(MAKE) test TEST=. TEST_DIR=./... COVERAGE_DIR=.coverage MINIMUM_COVERAGE=1
	@$(MAKE) build

version-check:
	@$(PYTHON) assets/scripts/version.py check

artifact-id:
	@$(PYTHON) assets/scripts/version.py artifact


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
	@git commit -m "ops: released v`cat VERSION | head -1`"
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
