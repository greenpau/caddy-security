#!/bin/bash
set -e

printf "Updating doc references\n"

ACV=`cat ../go-authcrunch/VERSION | head -1`
echo "go-authcrunch v${ACV}"

sed -i 's/go-authcrunch v[0-9]\.[0-9]*\.[0-9]*/go-authcrunch v'"${ACV}"'/' CONTRIBUTING.md
sed -i 's/go-authcrunch@v[0-9]\.[0-9]*\.[0-9]*/go-authcrunch@v'"${ACV}"'/' CONTRIBUTING.md
sed -i 's/go-authcrunch@v[0-9]\.[0-9]*\.[0-9]*/go-authcrunch@v'"${ACV}"'/' Makefile
sed -i 's/go-authcrunch v[0-9]\.[0-9]*\.[0-9]*/go-authcrunch v'"${ACV}"'/' go.mod

go mod tidy
go mod verify
