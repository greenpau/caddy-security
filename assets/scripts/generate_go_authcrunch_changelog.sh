#!/bin/bash
set -euo pipefail

MODULE_NAME="github.com/greenpau/go-authcrunch"
MODULE_REPO="https://github.com/greenpau/go-authcrunch"
CURRENT_REF="${CURRENT_REF:-HEAD}"
WORK_DIR="${RUNNER_TEMP:-/tmp}"

module_version_from_file() {
	awk -v module="${MODULE_NAME}" '$1 == module { print $2; exit }' go.mod
}

module_version_from_ref() {
	local ref="$1"

	git show "${ref}:go.mod" 2>/dev/null \
		| awk -v module="${MODULE_NAME}" '$1 == module { print $2; exit }' || true
}

previous_release_ref() {
	git describe --tags --abbrev=0 --match "v*" "${CURRENT_REF}^{commit}^" 2>/dev/null || true
}

module_repo_dir() {
	if [ -n "${GO_AUTHCRUNCH_REPO:-}" ]; then
		printf "%s\n" "${GO_AUTHCRUNCH_REPO}"
		return
	fi

	if [ -d "../go-authcrunch/.git" ]; then
		printf "%s\n" "../go-authcrunch"
		return
	fi

	local repo_dir
	repo_dir="$(mktemp -d "${WORK_DIR}/go-authcrunch.XXXXXX")"
	if git clone --filter=blob:none --no-checkout "${MODULE_REPO}.git" "${repo_dir}" >/dev/null 2>&1; then
		printf "%s\n" "${repo_dir}"
	fi
}

previous_ref="${PREVIOUS_REF:-$(previous_release_ref)}"
if [ -z "${previous_ref}" ]; then
	exit 0
fi

previous_version="${GO_AUTHCRUNCH_PREVIOUS_VERSION:-$(module_version_from_ref "${previous_ref}")}"
current_version="${GO_AUTHCRUNCH_CURRENT_VERSION:-$(module_version_from_file)}"

if [ -z "${previous_version}" ] || [ -z "${current_version}" ]; then
	exit 0
fi

if [ "${previous_version}" = "${current_version}" ]; then
	exit 0
fi

compare_url="${MODULE_REPO}/compare/${previous_version}...${current_version}"

printf "## go-authcrunch changes\n\n"
printf "%s was updated from \`%s\` to \`%s\`.\n\n" "${MODULE_NAME}" "${previous_version}" "${current_version}"
printf "Compare: %s\n" "${compare_url}"

repo_dir="$(module_repo_dir)"
if [ -z "${repo_dir}" ]; then
	exit 0
fi

if ! git -C "${repo_dir}" rev-parse --verify --quiet "refs/tags/${previous_version}" >/dev/null; then
	exit 0
fi

if ! git -C "${repo_dir}" rev-parse --verify --quiet "refs/tags/${current_version}" >/dev/null; then
	exit 0
fi

commit_log="$(
	git -C "${repo_dir}" log --reverse --format='- %s (%h)' \
		"${previous_version}..${current_version}" 2>/dev/null || true
)"

if [ -z "${commit_log}" ]; then
	exit 0
fi

printf "\n%s\n" "${commit_log}"
