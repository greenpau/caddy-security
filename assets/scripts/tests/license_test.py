"""The real maintenance target must never rewrite downloaded dependencies."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class LicenseTests(unittest.TestCase):
    def test_make_license_limits_writes_to_repository_sources(self):
        with tempfile.TemporaryDirectory(prefix="license-test-", dir=ROOT / "tmp") as directory:
            root = Path(directory)
            shutil.copyfile(ROOT / "Makefile", root / "Makefile")
            (root / ".gitignore").write_text("tmp/\nvendor/\n")
            owned = [root / "tracked.go", root / "new file.go"]
            excluded = [root / "tmp/suite/original.go", root / "vendor/dependency/original.go"]
            for path in owned + excluded:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("package fixture\n")
            subprocess.run(["git", "init", "-q", root], check=True, timeout=10)
            subprocess.run(["git", "add", "tracked.go"], cwd=root, check=True, timeout=10)
            scripts = root / "assets/scripts"
            scripts.mkdir(parents=True)
            downloads = scripts / "generate_downloads.sh"
            downloads.write_text("#!/bin/sh\nset -e\nprintf 'generated' > downloads-ran\n")
            downloads.chmod(0o700)
            tools = root / "test-tools"
            tools.mkdir()
            versioned = tools / "versioned"
            versioned.write_text("#!/bin/sh\nset -e\nwhile [ \"$1\" != -filepath ]; do shift; done\n"
                                 "shift\nprintf '// licensed\\n' >> \"$1\"\n")
            versioned.chmod(0o700)
            env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"])
            result = subprocess.run(["make", "license"], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            for path in owned:
                self.assertEqual(path.read_text(), "package fixture\n// licensed\n")
            for path in excluded:
                self.assertEqual(path.read_text(), "package fixture\n")
            self.assertEqual((root / "downloads-ran").read_text(), "generated")


if __name__ == "__main__":
    unittest.main()
