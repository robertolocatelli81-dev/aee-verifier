"""The version written in the code, the packaging metadata, the README and the CHANGELOG is one and the same, and
the README and the CHANGELOG give the same release date (0.2.0, the first release made as a package)."""

from __future__ import annotations

import datetime
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import aee_verifier  # noqa: E402

VERSION = "0.2.0"
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return fh.read()


class TestRelease(unittest.TestCase):
    def test_the_code_says_the_version(self):
        self.assertEqual(aee_verifier.__version__, VERSION)

    def test_pyproject_says_the_same_version_name_and_script(self):
        text = read("pyproject.toml")
        self.assertEqual(re.findall(r'(?m)^version = "([^"]*)"$', text), [VERSION])
        self.assertEqual(re.findall(r'(?m)^name = "([^"]*)"$', text), ["aee-verifier"])
        self.assertEqual(re.findall(r'(?m)^requires-python = "([^"]*)"$', text), [">=3.9"])
        self.assertEqual(re.findall(r'(?m)^dependencies = (.*)$', text), ["[]"])
        self.assertIn('aee-verify = "aee_verifier.cli:main"', text)

    def test_readme_and_changelog_give_the_version_and_one_release_date(self):
        readme = re.findall(r"(?m)^Version (\S+) — released on (\S+);", read("README.md"))
        changelog = re.findall(r"(?m)^## (\S+) — released on (\S+): ", read("CHANGELOG.md"))
        self.assertEqual(len(readme), 1, readme)
        self.assertEqual(readme[0][0], VERSION)
        self.assertEqual(changelog[0], readme[0])                 # the newest section is this release, same date
        self.assertTrue(DATE.fullmatch(readme[0][1]), readme)
        datetime.date.fromisoformat(readme[0][1])                 # a calendar date (2026-02-30 is refused)
        self.assertNotIn("unreleased", read("README.md").lower().split("## install")[0])
        self.assertEqual(len(re.findall(r"(?m)^## %s\b" % re.escape(VERSION), read("CHANGELOG.md"))), 1)

    def test_readme_install_lines_name_this_version(self):
        lines = [l for l in read("README.md").splitlines() if l.startswith("pip install")]
        self.assertEqual(len(lines), 3, lines)
        for line in lines:
            self.assertTrue(line.endswith("aee-verifier==" + VERSION) or line.endswith("@v" + VERSION), line)


if __name__ == "__main__":
    unittest.main()
