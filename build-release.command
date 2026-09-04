#!/bin/bash

# Build an installable Moodle plugin ZIP from the current committed revision.

set -eu

scriptdir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
outputdir="$scriptdir/dist"
temporary=""

cleanup() {
    if [ -n "$temporary" ] && [ -f "$temporary" ]; then
        rm -f "$temporary"
    fi

    if [ -t 0 ]; then
        printf '\nPress Return to close this window...'
        read -r _
    fi
}
trap cleanup EXIT

cd "$scriptdir"

if ! command -v git >/dev/null 2>&1; then
    printf 'Error: Git is required to build the release package.\n' >&2
    exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    printf 'Error: This script must remain inside the plugin Git repository.\n' >&2
    exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
    printf 'Error: Commit or stash tracked changes before building the package.\n' >&2
    printf 'Only committed files are included so release ZIPs remain reproducible.\n' >&2
    exit 1
fi

release="$(sed -nE "s/.*plugin->release[[:space:]]*=[[:space:]]*['\"]?([0-9]+).*/\1/p" version.php | head -n 1)"
if [ -z "$release" ]; then
    printf 'Error: Could not determine the plugin release from version.php.\n' >&2
    exit 1
fi

mkdir -p "$outputdir"

filename="auth_userkey-$release.zip"
output="$outputdir/$filename"
temporary="$outputdir/.$filename.tmp"

printf 'Building %s...\n' "$filename"
git archive \
    --format=zip \
    --prefix=userkey/ \
    --output="$temporary" \
    HEAD \
    -- . \
    ':(exclude).github' \
    ':(exclude).DS_Store' \
    ':(exclude)**/.DS_Store' \
    ':(exclude).gitignore' \
    ':(exclude).travis.yml' \
    ':(exclude)build-release.command'
mv -f "$temporary" "$output"
temporary=""

printf '\nRelease package created successfully:\n%s\n' "$output"

if command -v shasum >/dev/null 2>&1; then
    printf '\nSHA-256:\n'
    shasum -a 256 "$output"
fi
