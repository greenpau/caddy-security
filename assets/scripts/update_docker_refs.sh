#!/bin/bash
set -e

printf "Updating docker references\n"

TARGET_VERSION=`cat VERSION | head -1`

sed -i 's/caddy-security@v[0-9]\.[0-9]*\.[0-9]*/caddy-security@v'"${TARGET_VERSION}"'/' assets/docker/authp/Dockerfile

