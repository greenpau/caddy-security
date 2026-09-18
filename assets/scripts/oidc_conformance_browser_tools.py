"""Pinned Chrome for Testing downloads; all tools and trust stay repo-local."""

import os
import platform
import shutil
import stat
import urllib.request
import zipfile

CHROME_VERSION = '153.0.8010.47'
CHROME_REVISION = '1681091'
BASE = 'https://storage.googleapis.com/chrome-for-testing-public/' + CHROME_VERSION + '/'
PLATFORMS = {('Darwin', 'arm64'): 'mac-arm64', ('Linux', 'x86_64'): 'linux64'}
# SHA-256 of the immutable official CfT objects, downloaded via verified HTTPS.
# Version/revision: chrome-for-testing/last-known-good-versions-with-downloads.json
CHECKSUMS = {
    'mac-arm64': {'chrome': '939ef9dc3aa74240c929d793e123edab0fda89c5a9cfeb029686c34141d2ed58',
                  'chromedriver': '19ba80d6e611c9e47b17b0d3153d6a9536ce8d430d1e43118dca6061bc6c2cf9'},
    'linux64': {'chrome': '89778cbf7a852726b6f51649b2586b894c00737e81f8031733721560d21bbea7',
                'chromedriver': 'f8763f1e29b917f73e29f5fd4f037cf9c6b34ed419f350f73674adf795cc4813'},
}


def chrome_binary(directory):
    return directory / ('Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing'
                        if platform.system() == 'Darwin' else 'chrome')


def extract_zip(archive, destination, prefix, blocker):
    """Preserve executable modes and internal macOS framework symlinks safely."""
    with zipfile.ZipFile(archive) as source:
        for member in source.infolist():
            name = member.filename
            if not name.startswith(prefix + '/') or '..' in name.split('/') or '\\' in name:
                raise blocker('unexpected browser archive path')
            relative = name[len(prefix) + 1:]
            if not relative:
                continue
            target = destination / relative
            if not target.resolve().is_relative_to(destination.resolve()):
                raise blocker('browser archive path escaped extraction directory')
            target.parent.mkdir(parents=True, exist_ok=True)
            mode = member.external_attr >> 16
            if member.is_dir():
                target.mkdir(exist_ok=True)
            elif stat.S_ISLNK(mode):
                link = source.read(member).decode()
                if os.path.isabs(link) or not (target.parent / link).resolve().is_relative_to(destination.resolve()):
                    raise blocker('browser archive symlink escaped extraction directory')
                target.symlink_to(link)
            else:
                with source.open(member) as src, target.open('xb') as dst:
                    shutil.copyfileobj(src, dst)
                target.chmod(0o700 if mode & 0o111 else 0o600)


def install_browsers(work, command, write_json, digest, blocker):
    """Extract verified archives without installers, services or OS trust changes."""
    receipt = {}
    target_platform = PLATFORMS[platform.system(), platform.machine()]
    for name, checksum in CHECKSUMS[target_platform].items():
        print('Preparing ' + name + ' — headless Chrome screenshots and network evidence', flush=True)
        directory = work / 'tools' / name
        print('  Local path: ' + str(directory), flush=True)
        archive = work / 'tools' / (name + '-' + target_platform + '.zip')
        url = BASE + target_platform + '/' + archive.name
        if not archive.exists():
            with urllib.request.urlopen(url, timeout=120) as source, archive.open('xb') as target:
                shutil.copyfileobj(source, target)
        if digest(archive) != checksum:
            raise blocker('checksum mismatch for ' + name + '; preserve/remove the incomplete download before retrying')
        temporary = work / 'tools' / (name + '-extract')
        if temporary.exists():
            raise blocker('incomplete browser extraction: ' + str(temporary))
        temporary.mkdir(mode=0o700)
        extract_zip(archive, temporary, name + '-' + target_platform, blocker)
        manifest = {str(p.relative_to(temporary)): digest(p) for p in temporary.rglob('*') if p.is_file()}
        if directory.exists():
            installed = {str(p.relative_to(directory)): digest(p) for p in directory.rglob('*') if p.is_file()}
            if installed != manifest:
                raise blocker('installed browser differs from verified archive: ' + name)
            shutil.rmtree(temporary)
        else:
            temporary.rename(directory)
        receipt[name] = {'url': url, 'sha256': checksum, 'version': CHROME_VERSION,
                         'revision': CHROME_REVISION, 'files': manifest}
    return receipt
