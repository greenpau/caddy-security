#!/bin/bash
set -e

printf "Updating doc references\n"

TARGET_VERSION=`cat ../go-authcrunch/VERSION | head -1`
echo "go-authcrunch v${TARGET_VERSION}"

sed -i 's/go-authcrunch v[0-9]\.[0-9]*\.[0-9]*/go-authcrunch v'"${TARGET_VERSION}"'/' CONTRIBUTING.md
sed -i 's/go-authcrunch@v[0-9]\.[0-9]*\.[0-9]*/go-authcrunch@v'"${TARGET_VERSION}"'/' CONTRIBUTING.md
sed -i 's/go-authcrunch@v[0-9]\.[0-9]*\.[0-9]*/go-authcrunch@v'"${TARGET_VERSION}"'/' Makefile
sed -i 's/go-authcrunch v[0-9]\.[0-9]*\.[0-9]*/go-authcrunch v'"${TARGET_VERSION}"'/' go.mod

go mod tidy
go mod verify
