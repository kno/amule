#!/usr/bin/env python3
"""Integration tests for the clone-local Git hook bootstrap."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RULE = (
    "Prefer clear names, types, tests, and small structure; retain only non-obvious "
    "invariant, security, protocol, platform, or rationale comments; no narrative "
    "review comments unless asked.\n"
)


class SetupLocalGitHooksTest(unittest.TestCase):
    def run_git(self, cwd, *args):
        return subprocess.run(
            ["git", *args],
            cwd=cwd,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def run_bootstrap(self, cwd):
        return subprocess.run(
            ["sh", "scripts/setup-local-git-hooks.sh"],
            cwd=cwd,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_bootstrap_installs_hook_for_new_worktrees_without_overwriting(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory) / "repository"
            repository.mkdir()
            (repository / ".githooks").mkdir()
            (repository / "scripts").mkdir()
            shutil.copy2(PROJECT_ROOT / ".githooks" / "post-checkout", repository / ".githooks")
            shutil.copy2(PROJECT_ROOT / "scripts" / "setup-local-git-hooks.sh", repository / "scripts")

            self.run_git(repository, "init")
            self.run_git(repository, "config", "user.name", "Hook Test")
            self.run_git(repository, "config", "user.email", "hook-test@example.invalid")
            (repository / "seed").write_text("seed\n", encoding="utf-8")
            self.run_git(repository, "add", "seed", ".githooks", "scripts")
            self.run_git(repository, "commit", "-m", "seed")

            self.run_bootstrap(repository)
            hooks_path = self.run_git(repository, "config", "--local", "--get", "core.hooksPath").stdout.strip()

            linked = Path(temporary_directory) / "linked"
            self.run_git(repository, "worktree", "add", "-b", "linked", str(linked))
            local_rule = linked / "CLAUDE.local.md"
            self.assertEqual(RULE, local_rule.read_text(encoding="utf-8"))

            sentinel = "keep this file\n"
            local_rule.write_text(sentinel, encoding="utf-8")
            self.run_git(linked, "checkout", "-b", "preserved")
            self.assertEqual(sentinel, local_rule.read_text(encoding="utf-8"))

            local_rule.unlink()
            local_rule.symlink_to("missing-guidance")
            self.run_git(linked, "checkout", "-b", "symlink-preserved")
            self.assertTrue(local_rule.is_symlink())

            self.run_bootstrap(linked)
            linked_hooks_path = self.run_git(linked, "config", "--local", "--get", "core.hooksPath").stdout.strip()
            self.assertEqual(hooks_path, linked_hooks_path)


if __name__ == "__main__":
    unittest.main()
