#!/usr/bin/env python3
"""Check standalone caddy-authenticator archives in a GoReleaser output directory."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile
import zipfile


ROOT = Path(__file__).resolve().parents[2]


def check_archives(dist, root=ROOT):
    version = json.loads((dist / 'metadata.json').read_text())['version']
    if not isinstance(version, str) or not re.fullmatch(r'[0-9][0-9A-Za-z.+-]*', version):
        raise ValueError('invalid release version in metadata.json')
    expected = {}
    for system in ('linux', 'darwin', 'windows'):
        for arch in ('amd64', 'arm64'):
            extension = 'zip' if system == 'windows' else 'tar.gz'
            name = f'caddy-authenticator_{version}_{system}_{arch}.{extension}'
            expected[name] = system
    actual = {path.name for path in dist.glob('caddy-authenticator_*') if path.is_file()}
    if actual != set(expected):
        raise ValueError(f'archive matrix mismatch: missing={sorted(set(expected) - actual)}, extra={sorted(actual - set(expected))}')

    checksums = {}
    for line in (dist / f'authcrunch_{version}_SHA256SUMS').read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        if not re.fullmatch(r'[0-9a-f]{64}', digest) or name in checksums:
            raise ValueError('invalid or duplicate checksum entry')
        checksums[name] = digest
    documents = {
        'README.md': (root / 'cmd/caddy-authenticator/README.md').read_bytes(),
        'LICENSE': (root / 'LICENSE').read_bytes(),
    }
    for name, system in expected.items():
        path = dist / name
        if checksums.get(name) != hashlib.sha256(path.read_bytes()).hexdigest():
            raise ValueError(f'checksum mismatch: {name}')
        binary = 'caddy-authenticator.exe' if system == 'windows' else 'caddy-authenticator'
        wanted = set(documents) | {binary}
        if system == 'windows':
            with zipfile.ZipFile(path) as archive:
                if set(archive.namelist()) != wanted or len(archive.infolist()) != len(wanted):
                    raise ValueError(f'unexpected archive contents: {name}')
                data = {entry: archive.read(entry) for entry in wanted}
        else:
            with tarfile.open(path, 'r:gz') as archive:
                members = archive.getmembers()
                if set(archive.getnames()) != wanted or len(members) != len(wanted) or not all(entry.isfile() for entry in members):
                    raise ValueError(f'unexpected archive contents: {name}')
                if not archive.getmember(binary).mode & 0o100:
                    raise ValueError(f'binary is not executable: {name}')
                data = {entry: archive.extractfile(entry).read() for entry in wanted}
        if not data[binary]:
            raise ValueError(f'empty binary: {name}')
        if any(data[entry] != content for entry, content in documents.items()):
            raise ValueError(f'incorrect usage guide or license: {name}')
    return sorted(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dist', type=Path, help='snapshot/release output directory')
    args = parser.parse_args()
    try:
        archives = check_archives(args.dist)
    except (OSError, ValueError, KeyError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f'Archive check failed: {exc}', file=sys.stderr)
        return 1
    print(f'Validated {len(archives)} standalone archives, contents and SHA-256 checksums')
    return 0


if __name__ == '__main__':
    sys.exit(main())
