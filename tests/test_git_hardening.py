import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import threading
import unittest
from pathlib import Path
from unittest import mock

from harness import FactoryTestCase, git
from harness import FactoryEnv

SAFE = ("-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false")


class TickGitHardeningTests(FactoryTestCase):
    """The tick (sync + export + state branch) ignores planted hooks/fsmonitor and refuses planted drivers,
    filters and attributes, without any git action."""

    def setUp(self):
        super().setUp()
        e = self.env
        e.seed_project()
        e.seed_goal(project="zz-test-proj", title="zz-test hardening goal")
        e.seed_agent("zz-test-director", "director")
        self.h = e.home_dir
        self.bare = e.home / "origin.git"
        git("init", "-q", "--bare", "-b", "main", str(self.bare), cwd=e.home)
        git("remote", "add", "origin", str(self.bare), cwd=self.h)
        git("commit", "-q", "--allow-empty", "-m", "base", cwd=self.h)
        git("push", "-q", "-u", "origin", "main", cwd=self.h)
        self.ok("config", "git_push", "1")
        self.ok("config", "push_interval_s", "0")
        self.marker = e.home / "marker"
        self.clean_config = (self.h / ".git" / "config").read_text()  # the live-like allow-list keys only

    def g(self, *args):
        """git in the live-shaped repo without running anything the test planted."""
        return git(*SAFE, *args, cwd=self.h)

    def merge_code(self):
        other = self.env.home / "other"
        if not other.exists():
            git("clone", "-q", "-b", "main", str(self.bare), str(other), cwd=self.env.home)
        self.n = getattr(self, "n", 0) + 1
        (other / f"code{self.n}.txt").write_text("code\n")
        git("add", ".", cwd=other)
        git("commit", "-q", "-m", "code", cwd=other)
        git("push", "-q", "origin", "main", cwd=other)
        return git("rev-parse", "HEAD", cwd=other)

    def script(self, name):
        p = self.env.home / name
        p.write_text(f"#!/bin/sh\necho ran >> '{self.marker}'\n")
        p.chmod(0o755)
        return p

    def refused_events(self):
        return [json.loads(r["detail"]) for r in self.env.sql("SELECT detail FROM events WHERE action='git-config-refused'")]

    def refusal_msgs(self):
        return self.env.sql("SELECT subject FROM messages WHERE subject LIKE 'git config refused%'")

    # -- planted code does not run ----------------------------------------------------------
    def test_reference_transaction_hook_not_run_by_tick(self):
        hook = self.h / ".git" / "hooks" / "reference-transaction"
        hook.write_text(f"#!/bin/sh\necho ran >> '{self.marker}'\n")
        hook.chmod(0o755)
        new = self.merge_code()
        self.ok("plan", "G-001", "zz-test plan", agent="zz-test-director")
        self.ok("tick")
        self.assertEqual(self.g("rev-parse", "main"), new)  # fetch + ff-merge + state commit + push all ran
        self.assertTrue(self.g("rev-parse", "refs/heads/state"))
        self.assertFalse(self.marker.exists(), "reference-transaction hook ran")

    def test_fsmonitor_config_is_refused_and_overridden(self):
        git("config", "core.fsmonitor", str(self.script("fsm.sh")), cwd=self.h)
        self.merge_code()
        self.ok("tick")
        self.assertFalse(self.marker.exists(), "core.fsmonitor command ran")
        self.assertEqual(len(self.refused_events()), 1)  # not on the allow-list
        with self.env.load_factory() as mod:  # and even without the guard the -c override keeps it off
            self.assertEqual(mod.git_run(self.h, "status").returncode, 0)
        self.assertFalse(self.marker.exists(), "core.fsmonitor command ran under git_run")

    def test_git_protocol_and_proxy_not_executed(self):
        """(a) a git:// remote plus core.gitProxy: the protocol allow-list stops the fetch before the proxy runs."""
        git("config", "remote.origin.url", "git://example.invalid/factory.git", cwd=self.h)
        git("config", "core.gitProxy", str(self.script("p.sh")), cwd=self.h)
        git("config", "url.git://example.invalid/.insteadOf", "https://example.invalid/", cwd=self.h)
        with self.env.load_factory() as mod:
            for args in (("fetch", "origin"), ("ls-remote", "https://example.invalid/x.git")):
                p = mod.git_run(self.h, *args)
                self.assertNotEqual(p.returncode, 0, args)
                self.assertIn("not allowed", p.stderr)
            argv = mod.git_argv(self.h, "status")
            env = mod.gh_git_env()
        self.assertFalse(self.marker.exists(), "core.gitProxy ran")
        self.assertIn("protocol.allow=never", argv)
        self.assertIn("protocol.https.allow=always", argv)
        vals = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))}
        self.assertEqual((vals["protocol.allow"], vals["protocol.https.allow"], env["GIT_CONFIG_NOSYSTEM"]), ("never", "always", "1"))

    def test_hook_runs_without_the_override(self):
        """Control: the planted hook really fires for a plain git call, so the tests above prove something."""
        hook = self.h / ".git" / "hooks" / "reference-transaction"
        hook.write_text(f"#!/bin/sh\necho ran >> '{self.marker}'\n")
        hook.chmod(0o755)
        git("update-ref", "refs/heads/zz", "HEAD", cwd=self.h)
        self.assertTrue(self.marker.exists())

    # -- planted config refuses -------------------------------------------------------------
    def plant(self, kind):
        """Plant one thing the allow-list must refuse; returns the prefix of the key the event must list."""
        if kind == "driver":
            git("config", "merge.evil.driver", str(self.script("d.sh")), cwd=self.h)
            return "merge.evil.driver"
        if kind == "smudge":
            git("config", "filter.x.smudge", str(self.script("s.sh")), cwd=self.h)
            return "filter.x.smudge"
        if kind == "attrfile":
            git("config", "core.attributesFile", str(self.env.home / "attrs"), cwd=self.h)
            return "core.attributesfile"
        if kind == "gitproxy":
            git("config", "core.gitProxy", str(self.script("p.sh")), cwd=self.h)
            return "core.gitproxy"
        if kind == "url":
            git("config", "remote.origin.url", "git://example.invalid/factory.git", cwd=self.h)
            return "remote.origin.url="
        if kind == "insteadof":
            git("config", "url.git://example.invalid/.insteadOf", "https://github.com/", cwd=self.h)
            return "url."
        if kind in ("include-path", "include-if", "include-worktrees", "include-filter", "include-attrfile"):
            body = {"include-filter": '[filter "x"]\n\tclean = true\n',
                    "include-attrfile": "[core]\n\tattributesFile = /dev/null\n"}.get(kind, '[merge "evil"]\n\tdriver = true\n')
            (self.h / ".git" / "inc.cfg").write_text(body)
            if kind == "include-if":
                git("config", f"includeIf.gitdir:{self.h}/.git.path", "inc.cfg", cwd=self.h)
            elif kind == "include-worktrees":
                git("config", f"includeIf.gitdir:{self.h}/.git/worktrees/**.path", "inc.cfg", cwd=self.h)
            else:
                git("config", "include.path", "inc.cfg", cwd=self.h)
            return "includeif." if kind.startswith("include-") and kind in ("include-if", "include-worktrees") else "include.path"
        if kind in ("credential", "gpg", "ssh"):
            key = {"credential": "credential.helper", "gpg": "gpg.program", "ssh": "core.sshCommand"}[kind]
            git("config", key, "!true", cwd=self.h)
            return key.lower()
        (self.h / ".git" / "info").mkdir(exist_ok=True)
        (self.h / ".git" / "info" / "attributes").write_text("* merge=evil\n")
        return "info/attributes"

    KINDS = ("driver", "smudge", "attrfile", "info", "include-path", "include-if", "include-worktrees", "include-filter",
             "include-attrfile", "credential", "gpg", "ssh", "gitproxy", "url", "insteadof")

    def test_tick_refuses_and_takes_no_git_action(self):
        for kind in self.KINDS:
            with self.subTest(kind=kind):
                self.env.sql("DELETE FROM events WHERE action='git-config-refused'")
                self.env.sql("DELETE FROM messages WHERE subject LIKE 'git config refused%'")
                self.env.sql("DELETE FROM config WHERE key='last_git_config_refused_ts'")
                before_main = self.g("rev-parse", "main")
                before_origin = self.g("rev-parse", "refs/remotes/origin/main")
                state_before = git(*SAFE, "rev-parse", "-q", "--verify", "refs/heads/state", cwd=self.h) \
                    if self.has_state() else ""
                key = self.plant(kind)
                self.merge_code()
                self.ok("plan", "G-001", f"zz-test plan {kind}", agent="zz-test-director")
                self.ok("tick")
                self.ok("tick")
                self.assertEqual(self.g("rev-parse", "main"), before_main)  # no merge
                self.assertEqual(self.g("rev-parse", "refs/remotes/origin/main"), before_origin)  # no fetch
                self.assertEqual(self.has_state() and self.g("rev-parse", "refs/heads/state") or "", state_before)
                self.assertFalse(self.marker.exists())
                ev = self.refused_events()
                self.assertEqual(len(ev), 1, ev)  # at most hourly
                self.assertTrue(any(k.startswith(key) for k in ev[0]["keys"]), (key, ev[0]["keys"]))
                self.assertEqual(len(self.refusal_msgs()), 1)
                self.unplant(kind)
                self.ok("tick")
                self.assertEqual(self.g("rev-parse", "main"), self.g("rev-parse", "refs/remotes/origin/main"))
                self.assertNotEqual(self.g("rev-parse", "main"), before_main)  # synced again once clean

    def has_state(self):
        return bool(git(*SAFE, "for-each-ref", "refs/heads/state", cwd=self.h))

    def unplant(self, kind):
        """Put the repo config back to the live-like allow-list."""
        (self.h / ".git" / "config").write_text(self.clean_config)
        info = self.h / ".git" / "info" / "attributes"
        if info.exists():
            info.write_text("")

    def test_export_alone_refuses_state_commit(self):
        self.plant("driver")
        self.ok("plan", "G-001", "zz-test plan", agent="zz-test-director")
        self.ok("export")
        self.assertFalse(self.has_state())
        self.assertEqual(len(self.refused_events()), 1)

    def test_global_config_is_out_of_scope_xdg_attributes_refuse(self):
        """Known limit (G-010): ~/.gitconfig is not examined; a non-empty ~/.config/git/attributes still refuses."""
        uh = self.env.user_home
        (uh / ".gitconfig").write_text('[credential "https://github.com"]\n\thelper = !gh auth git-credential\n[merge "g"]\n\tdriver = true\n')
        new = self.merge_code()
        self.ok("tick")
        self.assertEqual(self.g("rev-parse", "main"), new)
        self.assertEqual(self.refused_events(), [])
        (uh / ".config" / "git").mkdir(parents=True)
        (uh / ".config" / "git" / "attributes").write_text("* merge=evil\n")
        self.merge_code()
        self.ok("tick")
        self.assertIn("~/.config/git/attributes", self.refused_events()[0]["keys"])

    def test_live_like_config_passes(self):
        """The allow-list covers every key the live ~/factory/.git/config has (branch names with dots and slashes too)."""
        for k, v in (("branch.factory/t-0001.remote", "origin"), ("branch.factory/t-0001.merge", "refs/heads/factory/t-0001"),
                     ("branch.a.b.remote", "origin"), ("extensions.worktreeConfig", "false")):
            git("config", k, v, cwd=self.h)
        with self.env.load_factory() as mod:
            self.assertEqual(mod.git_config_refusal(self.h), [])
            url = "https://github.com/example-org/factory.git"
            self.env.sql("UPDATE config SET value=? WHERE key='factory_remote_url'", (url,))
            mod.HOME = Path(mod.LIVE_HOME)  # the live rule: only the factory https url, no plain paths
            self.assertEqual(mod.git_config_refusal(self.h), [f"remote.origin.url={self.bare}"])
            git("config", "remote.origin.url", url, cwd=self.h)
            self.assertEqual(mod.git_config_refusal(self.h), [])
            git("config", "remote.origin.url", "https://github.com/evil/x.git", cwd=self.h)
            self.assertEqual(mod.git_config_refusal(self.h), ["remote.origin.url=https://github.com/evil/x.git"])

    URL = "https://github.com/example-org/factory.git"

    def live_checkout(self, origin):
        """A throwaway 'live' checkout whose origin is `origin`; returns its path."""
        live = self.env.home / "live"
        live.mkdir()
        git("init", "-q", "-b", "main", cwd=live)
        git("remote", "add", "origin", origin, cwd=live, inert_remote=True)
        return live

    def stored_url(self):
        rows = self.env.sql("SELECT value FROM config WHERE key='factory_remote_url'")
        return rows[0][0] or None if rows else None

    def test_remote_url_shape_rejects_dot_segments(self):
        """'.' / '..' path segments and percent-encoded dots never match the factory URL shape (TOFU and config set)."""
        bad = ("https://github.com/../factory.git", "https://github.com/./factory.git", "https://github.com/example-org/...git",
               "https://github.com/example-org/./factory.git",
               "https://github.com/%2e%2e/factory.git", "https://github.com/%2E./factory.git", "https://github.com/example-org/%2e%2e.git",
               "https://github.com/example-org/../factory.git")
        with self.env.load_factory() as mod:
            for url in bad:
                with self.subTest(url=url):
                    self.assertIsNone(mod._FACTORY_URL_SHAPE.fullmatch(url))
            self.assertTrue(mod._FACTORY_URL_SHAPE.fullmatch(self.URL))
            self.assertTrue(mod._FACTORY_URL_SHAPE.fullmatch("https://github.com/a.b/c..d.git"))

    def test_remote_url_tofu_ignores_a_dot_segment_origin(self):
        live = self.live_checkout("https://github.com/../factory.git")
        with self.env.load_factory() as mod:
            mod.LIVE_HOME = str(live)
            self.assertEqual(mod.factory_remote_url(), "")
        self.assertIsNone(self.stored_url())

    def test_config_set_factory_remote_url_validates_the_shape(self):
        for bad in ("https://example.invalid/x", "https://github.com/../x.git", "ext::sh -c x", "https://github.com/a/b"):
            with self.subTest(value=bad):
                self.refused(2, "config", "factory_remote_url", bad, agent="zz-test-director")
                self.assertIsNone(self.stored_url())
        self.ok("config", "factory_remote_url", self.URL, agent="zz-test-director")
        self.assertEqual(self.stored_url(), self.URL)
        self.refused(2, "config", "factory_remote_url", "https://github.com/../x.git", agent="zz-test-director")
        self.assertEqual(self.stored_url(), self.URL)
        self.ok("config", "factory_remote_url", "", agent="zz-test-director")  # empty = back to trust on first use
        self.assertIsNone(self.stored_url())

    def test_remote_url_tofu_stores_the_live_origin_and_records_an_event(self):
        live = self.live_checkout(self.URL)
        with self.env.load_factory() as mod:
            mod.LIVE_HOME = str(live)
            self.assertIsNone(self.stored_url())
            self.assertEqual(mod.factory_remote_url(), self.URL)
        self.assertEqual(self.stored_url(), self.URL)
        ev = self.env.sql("SELECT detail FROM events WHERE action='tofu' AND entity='config' AND entity_id='factory_remote_url'")
        self.assertEqual([r[0] for r in ev], [self.URL])
        live_cfg = live / ".git" / "config"
        git("config", "remote.origin.url", "https://github.com/evil/x.git", cwd=live)
        with self.env.load_factory() as mod:
            mod.LIVE_HOME = str(live)
            self.assertEqual(mod.factory_remote_url(), self.URL)  # stored: the live checkout is not read again
        self.assertTrue(live_cfg.exists())

    def test_remote_url_configured_wins_over_the_live_checkout(self):
        live = self.live_checkout(self.URL)
        other = "https://github.com/example-org/other.git"
        self.env.sql("UPDATE config SET value=? WHERE key='factory_remote_url'", (other,))
        with self.env.load_factory() as mod:
            mod.LIVE_HOME = str(live)
            self.assertEqual(mod.factory_remote_url(), other)
        self.assertEqual(self.env.sql("SELECT 1 FROM events WHERE action='tofu'"), [])

    def test_remote_url_malformed_or_missing_live_origin_fails_closed(self):
        for origin in ("ext::sh -c x", "https://github.com/example-org/factory", "git@github.com:example-org/factory.git",
                       "https://github.com/example-org/factory.git/extra"):
            with self.subTest(origin=origin):
                live = self.live_checkout(origin)
                with self.env.load_factory() as mod:
                    mod.LIVE_HOME = str(live)
                    self.assertEqual(mod.factory_remote_url(), "")
                    mod.HOME = Path(mod.LIVE_HOME)
                    git("config", "remote.origin.url", origin, cwd=self.h)
                    self.assertEqual(mod.git_config_refusal(self.h), [f"remote.origin.url={origin}"])
                self.assertIsNone(self.stored_url())
                self.assertEqual(self.env.sql("SELECT 1 FROM events WHERE action='tofu'"), [])
                shutil.rmtree(live)
        with self.env.load_factory() as mod:
            mod.LIVE_HOME = str(self.env.home / "no-such-live")
            self.assertEqual(mod.factory_remote_url(), "")

    def test_remote_guard_refuses_changed_origin_through_the_tick(self):
        self.env.sql("UPDATE config SET value=? WHERE key='factory_remote_url'", (str(self.bare),))
        self.merge_code()
        self.ok("tick")
        self.assertEqual(self.refused_events(), [])
        git("config", "remote.origin.url", "https://github.com/evil/x.git", cwd=self.h)
        self.merge_code()
        self.ok("tick")
        self.assertEqual(self.refused_events()[0]["keys"], ["remote.origin.url=https://github.com/evil/x.git"])

    def spawn_repo(self):
        self.env.seed_task(goal="G-001")
        self.env.sql("UPDATE projects SET repo_path=? WHERE id='zz-test-proj'", (str(self.h),))

    def prepare(self, role="coder"):
        with self.env.load_factory() as mod:
            con = mod.db()
            try:
                mod.prepare_worktree(con, "T-0001", role)
            except SystemExit as e:
                return e.code
        return 0

    def test_spawn_worktree_refuses_planted_config_before_fetch(self):
        self.spawn_repo()
        for kind in self.KINDS:
            with self.subTest(kind=kind):
                self.env.sql("DELETE FROM events WHERE action='git-config-refused'")
                self.env.sql("DELETE FROM config WHERE key='last_git_config_refused_ts'")
                key = self.plant(kind)
                before = self.g("rev-parse", "refs/remotes/origin/main")
                self.merge_code()
                self.assertEqual(self.prepare(), 4)  # spawn exits non-zero
                self.assertEqual(self.g("rev-parse", "refs/remotes/origin/main"), before)  # no fetch
                self.assertFalse(list((self.env.home_dir / "worktrees").glob("*")))
                self.assertFalse(self.marker.exists())
                ev = self.refused_events()
                self.assertEqual(len(ev), 1)
                self.assertTrue(any(k.startswith(key) for k in ev[0]["keys"]), ev)
                self.unplant(kind)
        self.assertEqual(self.prepare(), 0)  # live-like config again: the worktree is made
        self.assertTrue(list((self.env.home_dir / "worktrees").glob("*")))

    def commit_filter_attributes(self):
        """origin/main gets `* filter=x`, so any checkout runs a configured smudge filter."""
        other = self.env.home / "other"
        self.merge_code()
        (other / ".gitattributes").write_text("* filter=x\n")
        git("add", ".", cwd=other)
        git("commit", "-q", "-m", "attrs", cwd=other)
        git("push", "-q", "origin", "main", cwd=other)

    def test_worktree_add_does_not_run_includeif_smudge_filter(self):
        """(c) includeIf gitdir:.../worktrees/** applies only to the new worktree: refused on the includeIf itself, and
        when the first guard is bypassed the guard on the new worktree runs before any checkout."""
        self.spawn_repo()
        self.commit_filter_attributes()
        (self.h / ".git" / "inc.cfg").write_text(f'[filter "x"]\n\tsmudge = {self.script("s.sh")}\n')
        git("config", f"includeIf.gitdir:{self.h}/.git/worktrees/**.path", "inc.cfg", cwd=self.h)
        self.assertEqual(self.prepare(), 4)
        self.assertFalse(self.marker.exists())
        with self.env.load_factory() as mod:
            real, calls = mod.git_config_guard, []
            def first_passes(con, repo, always_event=False):
                calls.append(str(repo))
                return True if len(calls) == 1 else real(con, repo, always_event)
            mod.git_config_guard = first_passes
            con = mod.db()
            with self.assertRaises(SystemExit) as cm:
                mod.prepare_worktree(con, "T-0001", "coder")
        self.assertEqual(cm.exception.code, 4)
        self.assertEqual(len(calls), 2)
        self.assertTrue(calls[1].endswith("G-001-T-0001"), calls)  # the guard ran on the new worktree
        self.assertFalse(self.marker.exists(), "smudge filter ran during worktree add")
        self.assertFalse(list((self.env.home_dir / "worktrees").glob("*")))  # and the half-made worktree is gone

    def test_worktree_checkout_still_runs_after_guard(self):
        self.spawn_repo()
        self.merge_code()
        self.assertEqual(self.prepare(), 0)
        wt = next((self.env.home_dir / "worktrees").glob("*"))
        self.assertTrue(list(wt.glob("code*.txt")), "files must be checked out after --no-checkout + guard")

    def retry_switch_setup(self):
        """Existing coder worktree left detached one commit behind its branch, so `git switch` must rewrite files
        (and so run the smudge filter); the filter is configured in the project repo after the first spawn."""
        self.spawn_repo()
        self.commit_filter_attributes()
        self.assertEqual(self.prepare(), 0)
        wt = next((self.env.home_dir / "worktrees").glob("*"))
        self.env.sql("UPDATE tasks SET worktree=?, branch='factory/t-0001' WHERE id='T-0001'", (str(wt),))
        git("checkout", "-q", "--detach", "HEAD~1", cwd=wt)
        git("config", "filter.x.smudge", str(self.script("s.sh")), cwd=self.h)
        git("config", "filter.x.required", "true", cwd=self.h)

    def test_retry_switch_is_guarded(self):
        """B3a: a coder retry in an existing worktree runs `git switch`, which checks out; it is guarded too."""
        self.retry_switch_setup()
        self.assertEqual(self.prepare(), 4)
        self.assertFalse(self.marker.exists(), "smudge filter ran during the retry switch")
        self.assertEqual(self.refused_events()[0]["keys"][0][:7], "filter.")

    def test_retry_switch_control_marker_appears_when_guard_bypassed(self):
        """Control for test_retry_switch_is_guarded: identical setup and real git_run; only the guard is bypassed,
        and then the smudge filter DOES run."""
        self.retry_switch_setup()
        with self.env.load_factory() as mod:
            mod.git_config_guard = lambda con, repo, always_event=False: True
            mod.prepare_worktree(mod.db(), "T-0001", "coder")
        self.assertTrue(self.marker.exists(), "control: the filter must run when the guard is bypassed")

    def test_guard_refusal_leaves_no_worktree_or_branch(self):
        """The refused spawn (includeIf applies only to the new worktree) prunes the worktree entry and drops the branch."""
        self.spawn_repo()
        self.commit_filter_attributes()
        (self.h / ".git" / "inc.cfg").write_text(f'[filter "x"]\n\tsmudge = {self.script("s.sh")}\n')
        git("config", f"includeIf.gitdir:{self.h}/.git/worktrees/**.path", "inc.cfg", cwd=self.h)
        with self.env.load_factory() as mod:
            real, calls = mod.git_config_guard, []
            def first_passes(con, repo, always_event=False):
                calls.append(str(repo))
                return True if len(calls) == 1 else real(con, repo, always_event)
            mod.git_config_guard = first_passes
            with self.assertRaises(SystemExit) as cm:
                mod.prepare_worktree(mod.db(), "T-0001", "coder")
        self.assertEqual(cm.exception.code, 4)
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.g("worktree", "list", "--porcelain").count("worktree "), 1)  # only the main checkout
        self.assertEqual(self.g("branch", "--list", "factory/*"), "")

    def failing_checkout(self):
        """origin/main has `* filter=x` with a required smudge filter that exits 1, so `git checkout` fails (guard bypassed)."""
        self.spawn_repo()
        self.commit_filter_attributes()
        bad = self.env.home / "bad.sh"
        bad.write_text("#!/bin/sh\nexit 1\n")
        bad.chmod(0o755)
        git("config", "filter.x.smudge", str(bad), cwd=self.h)
        git("config", "filter.x.required", "true", cwd=self.h)

    def test_failed_checkout_removes_half_made_worktree_and_branch(self):
        self.failing_checkout()
        with self.env.load_factory() as mod:
            mod.git_config_guard = lambda con, repo, always_event=False: True
            with self.assertRaises(SystemExit) as cm:
                mod.prepare_worktree(mod.db(), "T-0001", "coder")
        self.assertNotEqual(cm.exception.code, 0)
        self.assertFalse(list((self.env.home_dir / "worktrees").glob("*")))
        self.assertNotIn("worktrees/", git("worktree", "list", cwd=self.h).replace(str(self.h), ""))
        self.assertEqual(git("worktree", "list", "--porcelain", cwd=self.h).count("worktree "), 1)
        self.assertEqual(git("branch", "--list", "factory/t-0001", cwd=self.h), "")

    def test_failed_checkout_keeps_preexisting_branch_and_other_worktree(self):
        self.failing_checkout()
        other = self.env.home_dir / "worktrees" / "other-wt"
        git("worktree", "add", "-q", "--no-checkout", "-b", "factory/t-0001", str(other), "origin/main", cwd=self.h)
        git("worktree", "remove", "--force", str(other), cwd=self.h)  # branch exists, its worktree is gone
        keep = self.env.home_dir / "worktrees" / "keep-wt"
        git("worktree", "add", "-q", "--no-checkout", "-b", "factory/keep", str(keep), "origin/main", cwd=self.h)
        with self.env.load_factory() as mod:
            mod.git_config_guard = lambda con, repo, always_event=False: True
            with self.assertRaises(SystemExit):
                mod.prepare_worktree(mod.db(), "T-0001", "coder")
        self.assertTrue(keep.exists())
        self.assertIn(str(keep), git("worktree", "list", cwd=self.h))
        self.assertIn("factory/t-0001", git("branch", "--list", "factory/t-0001", cwd=self.h))  # not created by this call

    def test_clean_refuses_fetch_on_planted_config(self):
        self.env.seed_task(goal="G-001")
        self.env.sql("UPDATE projects SET repo_path=? WHERE id='zz-test-proj'", (str(self.h),))
        self.env.sql("UPDATE tasks SET branch='factory/t-0001' WHERE id='T-0001'")
        self.env.seed_agent("zz-test-cleaner", "cleaner", goal="G-001")
        self.plant("include-path")
        before = self.g("rev-parse", "refs/remotes/origin/main")
        self.merge_code()
        self.env.run("clean", agent="zz-test-cleaner")
        self.assertEqual(self.g("rev-parse", "refs/remotes/origin/main"), before)
        self.assertEqual(len(self.refused_events()), 1)

    def test_commit_gpgsign_is_forced_off(self):
        """gpg.program is refused, and commit.gpgSign=true in repo config is overridden on the command line."""
        with self.env.load_factory() as mod:
            argv = mod.git_argv(self.h, "status")
        self.assertIn("commit.gpgSign=false", argv)
        self.assertIn("tag.gpgSign=false", argv)
        with self.env.load_factory() as mod:
            env = mod.gh_git_env()
        vals = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))}
        self.assertEqual((vals["commit.gpgSign"], vals["tag.gpgSign"]), ("false", "false"))

    def test_clean_repo_no_refusal_event(self):
        self.ok("tick")
        self.assertEqual(self.refused_events(), [])


class WorktreeOwnershipTests(FactoryTestCase):
    """G-002: worktree_owns_gitdir / _wt_git / _wt_remove accept a real linked worktree under <home>/worktrees and
    refuse everything else without running git inside it; a sibling worktree S is never touched."""

    def setUp(self):
        super().setUp()
        e = self.env
        self.repo = e.home / "repo"
        self.repo.mkdir()
        git("init", "-q", "-b", "main", str(self.repo), cwd=e.home)
        git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "--allow-empty", "-m", "base", cwd=self.repo)
        self.wts = e.home_dir / "worktrees"
        self.wts.mkdir()
        self.common = self.repo / ".git"
        self.A, self.S = self.add("A"), self.add("S")
        self.sibling_before = self.sibling_state()
        cm = e.load_factory()
        self.mod = cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)

    def add(self, name, parent=None):
        path = (parent or self.wts) / name
        git("worktree", "add", "-q", "-b", f"b-{name}", str(path), cwd=self.repo)
        return path

    def sibling_state(self):
        adm = self.common / "worktrees" / "S"
        return [hashlib.sha256((adm / f).read_bytes()).hexdigest() for f in ("index", "HEAD")]

    def assert_sibling_intact(self):
        self.assertTrue(self.S.is_dir())
        self.assertEqual(self.sibling_state(), self.sibling_before)

    def refuse(self, wt):
        """Every refusal: rc 126 from _wt_git and _wt_remove AND no git call with cwd under wt or naming wt
        (only `worktree list --porcelain` run in the repo is allowed)."""
        self.shim_git()
        start = len(self.calls())
        admin, why = self.mod.worktree_owns_gitdir(self.repo, wt)
        self.assertIsNone(admin, why)
        self.assertTrue(why)
        rc, _, err = self.mod._wt_git(self.repo, wt, "status")
        self.assertEqual(rc, 126, err)
        rc, _, err = self.mod._wt_remove(self.repo, wt)
        self.assertEqual(rc, 126, err)
        self.assert_no_git_call_on(wt, self.calls()[start:])
        self.assert_sibling_intact()
        return why

    def assert_no_git_call_on(self, wt, lines):
        # Whitelist: the shim logs the physical $PWD, so compare the logical and the resolved worktree
        # path. On a refusal the only allowed call is `worktree list --porcelain` run in the repo.
        w = str(wt)
        rw = os.path.realpath(w)
        rr = os.path.realpath(self.repo)
        for line in lines:
            cwd, argv = line.split("\t", 1)
            self.assertNotIn(cwd, {w, rw}, line)
            self.assertFalse(cwd.startswith(w + os.sep) or cwd.startswith(rw + os.sep), line)
            self.assertNotIn(w, argv, line)
            self.assertNotIn(rw, argv, line)
            # the only allowed call: git -C <repo> ... worktree list --porcelain (its $PWD is the caller's, not the repo's)
            toks = argv.split()
            self.assertEqual(toks[0], "-C", line)
            self.assertIn(toks[1], {str(self.repo), rr}, line)
            self.assertTrue(argv.endswith(" worktree list --porcelain"), line)

    def admin(self, name="A"):
        return self.common / "worktrees" / name

    # -- accepted ---------------------------------------------------------
    def test_real_worktree_accepted(self):
        admin, why = self.mod.worktree_owns_gitdir(self.repo, self.A)
        self.assertEqual((admin, why), (self.admin(), ""))

    def test_relative_pointers_accepted(self):
        r = self.add("R")
        (r / ".git").write_text("gitdir: ../../../repo/.git/worktrees/R\n")
        (self.admin("R") / "gitdir").write_text("../../../../factory/worktrees/R/.git\n")
        admin, why = self.mod.worktree_owns_gitdir(self.repo, r)
        self.assertEqual((admin, why), (self.admin("R"), ""))

    # -- refused ----------------------------------------------------------
    def test_a_symlink_to_sibling(self):
        (self.wts / "L").symlink_to(self.S)
        self.refuse(self.wts / "L")

    def test_b_symlinked_parent(self):
        (self.wts / "P").symlink_to(self.wts)
        self.refuse(self.wts / "P" / "S")

    def test_c_dotgit_symlink(self):
        c = self.wts / "C"
        c.mkdir()
        (c / ".git").symlink_to(self.S / ".git")
        self.refuse(c)

    def test_d_dotgit_directory(self):
        d = self.wts / "D"
        (d / ".git").mkdir(parents=True)
        self.refuse(d)

    def test_e_back_pointer_names_sibling(self):
        x = self.wts / "X"
        x.mkdir()
        (x / ".git").write_text(f"gitdir: {self.admin('S')}\n")
        self.refuse(x)

    def test_f_gitdir_shapes(self):
        for text in (f"{self.common}/worktrees/../worktrees/A", f"{self.common}/worktrees/a/b",
                     f"{self.repo}/outside", "../../../repo/.git/worktrees/../worktrees/A", f"{self.common}/worktrees/./A"):
            with self.subTest(text=text):
                saved = (self.A / ".git").read_text()
                (self.A / ".git").write_text(f"gitdir: {text}\n")
                try:
                    self.refuse(self.A)
                finally:
                    (self.A / ".git").write_text(saved)
        (self.A / ".git").write_text("gitdir: " + str(self.admin()) + "\nextra\n")
        self.refuse(self.A)

    def test_g_admin_gitdir_symlink(self):
        back = self.admin() / "gitdir"
        real = self.admin() / "gitdir.real"
        back.rename(real)
        back.symlink_to(real)
        self.refuse(self.A)

    def test_g_admin_gitdir_names_symlink_alias(self):
        (self.wts / "alias").symlink_to(self.A)
        (self.admin() / "gitdir").write_text(f"{self.wts}/alias/.git\n")
        why = self.refuse(self.A)
        self.assertIn("back pointer", why)
        # git itself lists the alias path, which would refuse this for another reason; make it list A so that
        # only the UNRESOLVED back-pointer compare is left to catch the alias
        listing = (0, f"worktree {self.A}\nHEAD {'1' * 40}\ndetached", "")
        with mock.patch.object(self.mod, "_git_rc", return_value=listing):
            admin, why = self.mod.worktree_owns_gitdir(self.repo, self.A)
        self.assertIsNone(admin)
        self.assertIn("back pointer", why)

    def test_h_forged_commondir(self):
        other = self.env.home / "other"
        other.mkdir()
        git("init", "-q", "-b", "main", str(other), cwd=self.env.home)
        (self.admin() / "commondir").write_text(f"{other}/.git\n")
        self.refuse(self.A)

    def test_i_hand_made_admin_not_listed(self):
        h = self.wts / "H"
        h.mkdir()
        (h / ".git").write_text(f"gitdir: {self.admin('H')}\n")
        self.admin("H").mkdir()
        (self.admin("H") / "gitdir").write_text(f"{h}/.git\n")
        (self.admin("H") / "commondir").write_text("../..\n")
        self.refuse(h)

    def test_j_not_a_direct_child(self):
        nested = self.add("N", parent=self.make_dir(self.wts / "sub"))
        self.refuse(nested)
        elsewhere = self.add("E", parent=self.make_dir(self.env.home / "elsewhere"))
        self.refuse(elsewhere)
        self.refuse(self.wts)

    @staticmethod
    def make_dir(p):
        p.mkdir()
        return p

    # -- the choke point --------------------------------------------------
    def shim_git(self):
        if getattr(self, "log", None):
            return
        real = shutil.which("git")
        shim_dir = self.env.home / "shim"
        shim_dir.mkdir()
        self.log = self.env.home / "git-calls.log"
        shim = shim_dir / "git"
        shim.write_text(f'#!/bin/sh\nprintf \'%s\\t%s\\n\' "$PWD" "$*" >> {self.log}\nexec {real} "$@"\n')
        shim.chmod(0o755)
        patch = mock.patch.dict(os.environ, {"PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}"})
        patch.start()
        self.addCleanup(patch.stop)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_refusals_make_no_git_call_naming_or_inside_the_worktree(self):
        (self.wts / "L").symlink_to(self.S)
        c = self.wts / "C"
        c.mkdir()
        (c / ".git").symlink_to(self.S / ".git")
        x = self.wts / "X"
        x.mkdir()
        (x / ".git").write_text(f"gitdir: {self.admin('S')}\n")
        h = self.wts / "H"
        h.mkdir()
        (h / ".git").write_text(f"gitdir: {self.admin('H')}\n")
        self.admin("H").mkdir()
        (self.admin("H") / "gitdir").write_text(f"{h}/.git\n")
        (self.admin("H") / "commondir").write_text("../..\n")
        self.shim_git()
        # positive control: the helper is not vacuous (accepts the one allowed call, rejects each bad shape)
        ok = f"/cwd\t-C {self.repo} -c core.hooksPath=/dev/null worktree list --porcelain"
        self.assert_no_git_call_on(self.wts / "L", [ok])
        for bad in (f"{self.S}\t-C {self.repo} worktree list --porcelain",
                    f"{os.path.realpath(self.S)}/sub\t-C {self.repo} worktree list --porcelain",
                    f"/cwd\t-C {self.repo} status",
                    f"/cwd\t-C {os.path.realpath(self.S)} worktree list --porcelain",
                    f"/cwd\t-C {self.repo} rev-parse HEAD"):
            with self.assertRaises(AssertionError, msg=bad):
                self.assert_no_git_call_on(self.wts / "L", [bad])
        for wt in (self.wts / "L", c, x, h):
            start = len(self.calls())
            self.mod._wt_git(self.repo, wt, "status")
            self.mod._wt_remove(self.repo, wt)
            self.assert_no_git_call_on(wt, self.calls()[start:])
        self.assert_sibling_intact()

    def test_accept_passes_explicit_git_dir_and_work_tree(self):
        self.shim_git()
        rc, out, err = self.mod._wt_git(self.repo, self.A, "rev-parse", "--show-toplevel")
        self.assertEqual((rc, out), (0, str(self.A)), err)
        last = self.calls()[-1]
        cwd, argv = last.split("\t", 1)
        self.assertEqual(cwd, str(self.A))
        self.assertIn(f"--git-dir={self.admin()}", argv)
        self.assertIn(f"--work-tree={self.A}", argv)

    def test_remove_accepted_worktree_leaves_sibling(self):
        rc, _, err = self.mod._wt_remove(self.repo, self.A)
        self.assertEqual(rc, 0, err)
        self.assertFalse(self.A.exists())
        self.assert_sibling_intact()


class WorktreeReuseSpawnTests(FactoryTestCase):
    """G-002 C: `factory spawn coder` with worktree_reuse=1 claims a free pooled worktree of the project, resets it, and
    falls back to a fresh worktree (fail closed) on any problem. Real temp repo + local bare origin; the pool row comes
    from a real `factory clean` of a merged task. Spawns run as subprocesses through the harness."""

    def setUp(self):
        super().setUp()
        self.build()

    def build(self):
        """(Re)build repo, origin, project and goal inside self.env."""
        e = self.env
        self.origin = e.home / "origin.git"
        self.repo = e.home / "repo"
        git("init", "-q", "--bare", "-b", "main", str(self.origin), cwd=e.home)
        git("clone", "-q", str(self.origin), str(self.repo), cwd=e.home)
        git("checkout", "-q", "-b", "main", cwd=self.repo)
        (self.repo / "README").write_text("x\n")
        (self.repo / ".gitignore").write_text("node_modules/\n")
        git("add", "README", ".gitignore", cwd=self.repo)
        git("commit", "-q", "-m", "init", cwd=self.repo)
        git("push", "-q", "-u", "origin", "main", cwd=self.repo)
        self.wts = e.home_dir / "worktrees"
        self.wts.mkdir(exist_ok=True)
        e.seed_project("zz-test-proj")
        e.sql("UPDATE projects SET repo_path=? WHERE id='zz-test-proj'", (str(self.repo),))
        e.seed_goal(project="zz-test-proj")
        e.seed_agent("zz-test-cleaner", "cleaner", goal="G-001")
        self.set_cfg(worktree_reuse="1", worktree_pool_max="2")

    def set_cfg(self, **kv):
        for k, v in kv.items():
            self.env.sql("INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, v))

    def rows(self):
        return self.env.sql("SELECT * FROM worktree_pool ORDER BY path")

    def events(self, action):
        return self.env.sql("SELECT detail FROM events WHERE action=?", (action,))

    def tw(self, tid):
        return self.env.sql("SELECT worktree FROM tasks WHERE id=?", (tid,))[0]["worktree"]

    def pooled(self, n=1, node_modules=True):
        """A merged, pushed task T-000<n> whose worktree a real `factory clean` pools; its path."""
        e = self.env
        tid, branch = f"T-000{n}", f"factory/t-000{n}"
        url = f"https://github.com/zz-test/repo/pull/{n}"
        wt = self.wts / f"G-001-{tid}"
        git("worktree", "add", "-q", "-b", branch, str(wt), "origin/main", cwd=self.repo)
        (wt / f"f{n}").write_text("work\n")
        git("add", f"f{n}", cwd=wt)
        git("commit", "-q", "-m", f"work {n}", cwd=wt)
        git("push", "-q", "origin", branch, cwd=wt)
        e.seed_task(tid, status="done", pr_url=url)
        e.sql("UPDATE tasks SET worktree=?, branch=? WHERE id=?", (str(wt), branch, tid))
        e.seed_pr(url, sha=git("rev-parse", "HEAD", cwd=wt), state="MERGED")
        if node_modules:
            (wt / "node_modules" / "pkg").mkdir(parents=True)
            (wt / "node_modules" / "pkg" / "index.js").write_text("module.exports = 1\n")
        p = self.ok("clean", agent="zz-test-cleaner")
        self.assertIn("released to pool", p.stdout)
        path = str(wt.resolve())
        self.assertEqual([r["path"] for r in self.rows() if r["state"] == "free" and r["path"] == path], [path])
        return wt.resolve()

    def todo(self, n):
        self.env.seed_task(f"T-000{n}", status="todo", pr_url=None)

    def spawn(self, n, extra_env=None, expect=0):
        p = self.env.run("spawn", "coder", "--goal", "G-001", "--task", f"T-000{n}", "--name", f"zz-test-c{n}", extra_env=extra_env)
        self.assertEqual(p.returncode, expect, f"rc={p.returncode}\n{p.stdout}\n{p.stderr}")
        self.assertNotIn("QUEUED", p.stdout)
        return p

    def admin(self, wt):
        return Path(git("rev-parse", "--absolute-git-dir", cwd=wt))

    def shim(self, body):
        """A git shim ahead of PATH: `body` is sh run before the real git ($* is the git argv)."""
        d = self.env.home / "shim"
        d.mkdir(exist_ok=True)
        log = self.env.home / "git-calls.log"
        sh = d / "git"
        sh.write_text(f'#!/bin/sh\n{body}\nprintf \'%s\\t%s\\n\' "" "$*" >> {log}\nexec {shutil.which("git")} "$@"\n')
        sh.chmod(0o755)
        return {"PATH": f"{d}{os.pathsep}{self.env.stub_bin}{os.pathsep}{os.environ['PATH']}"}, log

    # 1 flag off
    def test_flag_off_creates_fresh_worktree_and_leaves_pool_alone(self):
        P = self.pooled()
        self.set_cfg(worktree_reuse="0")
        before = self.rows()
        self.todo(2)
        self.spawn(2)
        self.assertEqual(self.tw("T-0002"), str(self.wts / "G-001-T-0002"))
        self.assertTrue((self.wts / "G-001-T-0002").is_dir())
        self.assertEqual(self.rows(), before)
        self.assertEqual(self.env.sql("SELECT count(*) c FROM worktree_pool WHERE state='claimed'")[0]["c"], 0)
        self.assertEqual(self.events("worktree-reused"), [])
        self.assertTrue(P.exists())

    # 2 reuse
    def test_reuse_claims_resets_and_keeps_ignored_files(self):
        P = self.pooled()
        (self.repo / "later").write_text("new\n")
        git("add", "later", cwd=self.repo)
        git("commit", "-q", "-m", "later", cwd=self.repo)
        git("push", "-q", "origin", "main", cwd=self.repo)
        self.todo(2)
        self.spawn(2)
        self.assertEqual(self.tw("T-0002"), str(P))
        rows = self.rows()
        self.assertEqual([(r["path"], r["state"], r["task_id"], r["reset_ok"]) for r in rows], [(str(P), "claimed", "T-0002", 1)])
        self.assertEqual(git("symbolic-ref", "HEAD", cwd=P), "refs/heads/factory/t-0002")
        self.assertEqual(git("rev-parse", "HEAD", cwd=P), git("rev-parse", "origin/main", cwd=self.repo))
        self.assertEqual((P / "node_modules" / "pkg" / "index.js").read_text(), "module.exports = 1\n")
        self.assertTrue((P / "later").exists())
        ev = self.events("worktree-reused")
        self.assertEqual(len(ev), 1)
        d = json.loads(ev[0]["detail"])
        self.assertEqual((d["path"], d["task"], d["from_task"]), (str(P), "T-0002", "T-0001"))
        self.assertEqual(self.env.sql("SELECT branch FROM tasks WHERE id='T-0002'")[0]["branch"], "factory/t-0002")
        self.assertFalse((self.wts / "G-001-T-0002").exists())

    # 3 untracked removed
    def test_untracked_and_modified_state_removed_ignored_kept(self):
        P = self.pooled()
        (P / "u.txt").write_text("u\n")
        (P / "d").mkdir()
        (P / "d" / "x").write_text("x\n")
        (P / "README").write_text("modified\n")
        (P / "staged").write_text("s\n")
        git("add", "staged", cwd=P)
        git("init", "-q", "n", cwd=P)
        (P / "n" / "inner").write_text("i\n")
        self.todo(2)
        self.spawn(2)
        self.assertEqual(self.tw("T-0002"), str(P))
        self.assertEqual(git("status", "--porcelain", "--untracked-files=all", cwd=P), "")
        for gone in ("u.txt", "d", "staged", "n"):
            self.assertFalse((P / gone).exists(), gone)
        self.assertEqual((P / "README").read_text(), "x\n")
        self.assertTrue((P / "node_modules" / "pkg" / "index.js").exists())

    # 4 per-worktree config + guard order
    def test_config_worktree_removed_and_guard_runs_before_checkout(self):
        P = self.pooled()
        cw = self.admin(P) / "config.worktree"
        cw.write_text("[user]\n\tname = previous-task\n")
        env, log = self.shim("")
        sh = self.env.home / "shim" / "git"
        sh.write_text(f'#!/bin/sh\nif [ -e "{cw}" ]; then c=1; else c=0; fi\n'
                      f'printf \'%s\\t%s\\n\' "$c" "$*" >> {log}\nexec {shutil.which("git")} "$@"\n')
        self.todo(2)
        self.spawn(2, extra_env=env)
        self.assertFalse(cw.exists())
        self.assertEqual(self.tw("T-0002"), str(P))
        calls = [l.split("\t", 1) for l in log.read_text().splitlines()]
        checkouts = [i for i, (_, a) in enumerate(calls) if " checkout " in f" {a} " and "-B" in a]
        self.assertTrue(checkouts)
        self.assertEqual(calls[checkouts[0]][0], "0", "config.worktree still existed at checkout")
        self.assertTrue(any(c == "1" and "config" in a and "--file" in a for c, a in calls[:checkouts[0]]),
                        "the guard never read config.worktree before the checkout")

    def test_forbidden_config_worktree_refuses_spawn_and_runs_nothing(self):
        P = self.pooled()
        marker = self.env.home / "marker"
        script = self.env.home / "mon.sh"
        script.write_text(f"#!/bin/sh\ntouch {marker}\n")
        script.chmod(0o755)
        (self.admin(P) / "config.worktree").write_text(f"[core]\n\tfsmonitor = {script}\n")
        self.todo(2)
        p = self.spawn(2, expect=4)
        self.assertIn("spawn refused: git config in", p.stderr + p.stdout)
        self.assertFalse(marker.exists())
        self.assertEqual([r["state"] for r in self.rows()], ["free"])

    # 5 leftover git state
    def test_leftover_git_state_removed(self):
        P = self.pooled()
        adm = self.admin(P)
        sha = git("rev-parse", "HEAD", cwd=P)
        for n in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "BISECT_LOG", "MERGE_MSG", "ORIG_HEAD"):
            (adm / n).write_text(sha + "\n")
        for d in ("rebase-merge", "rebase-apply", "sequencer"):
            (adm / d).mkdir()
            (adm / d / "x").write_text("x\n")
        git("update-ref", "refs/worktree/x", "HEAD", cwd=P)
        git("update-ref", "refs/bisect/bad", "HEAD", cwd=P)
        self.todo(2)
        self.spawn(2)
        self.assertEqual(self.tw("T-0002"), str(P))
        for n in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "BISECT_LOG", "MERGE_MSG", "ORIG_HEAD", "rebase-merge", "rebase-apply", "sequencer"):
            self.assertFalse((adm / n).exists(), n)
        self.assertEqual(git("for-each-ref", "refs/worktree", "refs/bisect", cwd=P), "")

    # 6 fallback, fail closed
    def test_reset_failure_falls_back_to_fresh_worktree(self):
        P = self.pooled()
        env, _ = self.shim('case " $* " in *" reset "*) echo "boom" >&2; exit 1;; esac')
        self.todo(2)
        self.spawn(2, extra_env=env)
        fresh = self.wts / "G-001-T-0002"
        self.assertEqual(self.tw("T-0002"), str(fresh))
        self.assertTrue(fresh.is_dir())
        self.assertFalse(P.exists())
        self.assertEqual(self.rows(), [])
        ev = self.events("worktree-reuse-failed")
        self.assertEqual(len(ev), 1)
        self.assertEqual(json.loads(ev[0]["detail"])["step"], "reset")
        self.assertEqual(self.events("worktree-reused"), [])

    def test_branch_checked_out_elsewhere_is_a_step_failure(self):
        P = self.pooled()
        other = self.wts / "other"
        git("worktree", "add", "-q", "-b", "factory/t-0002", str(other), "origin/main", cwd=self.repo)
        self.todo(2)
        self.spawn(2, expect=1)  # the fresh path hits the same branch conflict, exactly as today
        self.assertFalse(P.exists())
        self.assertEqual(self.rows(), [])
        self.assertEqual(json.loads(self.events("worktree-reuse-failed")[0]["detail"])["step"], "checkout")
        self.assertTrue(other.is_dir())

    def test_symlinked_and_forged_pool_rows_keep_dirs_and_siblings(self):
        S = self.pooled(1, node_modules=False)
        forged = self.pooled(4, node_modules=False)
        self.env.sql("UPDATE worktree_pool SET state='claimed', task_id='T-0001', claimed_at='t' WHERE path=?", (str(S),))
        (forged / ".git").write_text(f"gitdir: {self.admin(S)}\n")
        link = self.wts / "link"
        link.symlink_to(S)
        self.env.sql("INSERT INTO worktree_pool(path,project_id,state,task_id,reset_ok,claimed_at,released_at) "
                     "VALUES(?,?,?,NULL,1,NULL,'2026-01-01T00:00:00+00:00')", (str(link), "zz-test-proj", "free"))
        snap = lambda: [hashlib.sha256((self.admin(S) / n).read_bytes()).hexdigest() for n in ("HEAD", "index")]
        before = snap()
        self.todo(2)
        self.spawn(2)
        self.assertEqual(snap(), before)
        self.assertTrue(S.is_dir() and forged.is_dir() and link.is_symlink())
        self.assertEqual(len(self.events("worktree-gitdir-mismatch")), 2)
        self.assertEqual([r["task_id"] for r in self.rows()], ["T-0001"])
        self.assertEqual(self.tw("T-0002"), str(self.wts / "G-001-T-0002"))
        self.assertTrue((self.wts / "G-001-T-0002").is_dir())

    def test_repo_level_planted_config_still_exits_4(self):
        P = self.pooled()
        git("config", "core.fsmonitor", "/bin/true", cwd=self.repo)
        self.todo(2)
        p = self.spawn(2, expect=4)
        self.assertIn("spawn refused: git config in", p.stderr + p.stdout)
        self.assertEqual([(r["path"], r["state"]) for r in self.rows()], [(str(P), "free")])

    # 7, 8 concurrency
    def race(self, free_rows):
        """Fresh env, `free_rows` pooled worktrees, T-0002 and T-0003 spawned together; their worktrees."""
        self.env = FactoryEnv()
        self.addCleanup(self.env.cleanup)
        self.build()
        pool = [self.pooled(n) for n in (1, 4)[:free_rows]]
        self.todo(2)
        self.todo(3)
        gate = threading.Barrier(2)
        out = {}
        lock_dir = self.env.home / "locked-stubs"  # the pane/gh stubs keep state in one JSON file and are not safe to run twice at once
        lock_dir.mkdir()
        for tool in ("herdr", "gh", "hc"):
            wrapper = lock_dir / tool
            wrapper.write_text(f'#!/bin/sh\nexec flock {self.env.home}/stub.lock {self.env.stub_bin}/{tool} "$@"\n')
            wrapper.chmod(0o755)
        path = {"PATH": f"{lock_dir}{os.pathsep}{self.env.stub_bin}{os.pathsep}{os.environ['PATH']}"}

        def go(n):
            gate.wait()
            out[n] = self.env.run("spawn", "coder", "--goal", "G-001", "--task", f"T-000{n}", "--name", f"zz-test-c{n}", extra_env=path)

        ts = [threading.Thread(target=go, args=(n,)) for n in (2, 3)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        for n, p in out.items():
            self.assertEqual(p.returncode, 0, f"T-000{n}: {p.stdout}\n{p.stderr}")
            self.assertNotIn("QUEUED", p.stdout)
        return [str(x) for x in pool], [self.tw("T-0002"), self.tw("T-0003")]

    def test_concurrent_spawns_one_free_row_five_rounds(self):
        for rnd in range(5):
            pool, got = self.race(1)
            self.assertEqual(len(set(got)), 2, f"round {rnd}: both tasks got {got}")
            self.assertEqual(sum(g == pool[0] for g in got), 1, f"round {rnd}: {got}")
            self.assertEqual(sum(g.endswith(("G-001-T-0002", "G-001-T-0003")) for g in got), 1)
            self.assertEqual(self.env.sql("SELECT count(*) c FROM worktree_pool WHERE state='claimed'")[0]["c"], 1)
            self.assertEqual(self.env.sql("SELECT task_id, count(*) c FROM worktree_pool WHERE state='claimed' GROUP BY task_id HAVING count(*)>1"), [])
            print(f"concurrency round {rnd + 1}/5: pool={pool[0]} T-0002={got[0]} T-0003={got[1]}")

    def test_concurrent_spawns_two_free_rows_both_reused(self):
        pool, got = self.race(2)
        self.assertEqual(sorted(got), sorted(pool))
        self.assertEqual(self.env.sql("SELECT count(*) c FROM worktree_pool WHERE state='claimed'")[0]["c"], 2)
        self.assertEqual(self.env.sql("SELECT task_id, count(*) c FROM worktree_pool WHERE state='claimed' GROUP BY task_id HAVING count(*)>1"), [])

    def test_claim_is_exclusive_between_its_select_and_its_update(self):
        """Deterministic race: a second connection tries to claim exactly between pool_claim's SELECT and UPDATE."""
        P = self.pooled()
        self.todo(2)
        self.todo(3)
        cm = self.env.load_factory()
        mod = cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        con1, con2 = mod.db(), mod.db()
        con2.execute("PRAGMA busy_timeout=100")
        seen = []

        class Racer:
            def __init__(self, con):
                self.con = con

            def execute(self, sql, *a):
                r = self.con.execute(sql, *a)
                if sql.startswith("SELECT path FROM worktree_pool") and not seen:
                    try:
                        seen.append(mod.pool_claim(con2, "zz-test-proj", "T-0003"))
                    except sqlite3.OperationalError as e:
                        seen.append(f"locked: {e}")
                return r

        got = mod.pool_claim(Racer(con1), "zz-test-proj", "T-0002")
        self.assertEqual(got, str(P))
        self.assertEqual(len(seen), 1)
        self.assertTrue(seen[0] is None or seen[0].startswith("locked"), f"second claimer got {seen[0]!r}")
        self.assertEqual([(r["task_id"], r["state"]) for r in self.rows()], [("T-0002", "claimed")])

    # 9 crash recovery
    def claimed_for(self, P, reset_ok):
        self.todo(2)
        self.env.sql("UPDATE worktree_pool SET state='claimed', task_id='T-0002', reset_ok=?, claimed_at='t' WHERE path=?", (reset_ok, str(P)))
        self.env.sql("UPDATE tasks SET worktree=?, branch='factory/t-0002' WHERE id='T-0002'", (str(P),))

    def test_crash_before_reset_ok_reruns_the_reset(self):
        P = self.pooled()
        self.claimed_for(P, 0)
        (P / "leftover.txt").write_text("x\n")
        self.spawn(2)
        self.assertFalse((P / "leftover.txt").exists())
        self.assertEqual([(r["task_id"], r["reset_ok"]) for r in self.rows()], [("T-0002", 1)])
        self.assertEqual(git("symbolic-ref", "HEAD", cwd=P), "refs/heads/factory/t-0002")
        self.assertEqual(self.tw("T-0002"), str(P))

    def test_claimed_row_with_missing_directory_is_dropped(self):
        P = self.pooled()
        self.claimed_for(P, 0)
        self.assertEqual(self.mod_rm(P), 0)
        self.spawn(2)
        self.assertEqual(self.rows(), [])
        self.assertEqual(self.tw("T-0002"), str(self.wts / "G-001-T-0002"))

    def mod_rm(self, P):
        git("worktree", "remove", "--force", str(P), cwd=self.repo)
        return 0

    def test_reset_done_existing_worktree_path_unchanged(self):
        P = self.pooled()
        git("checkout", "-q", "-B", "factory/t-0002", "origin/main", cwd=P)
        self.claimed_for(P, 1)
        (P / "wip.txt").write_text("work in progress\n")
        self.spawn(2)
        self.assertEqual((P / "wip.txt").read_text(), "work in progress\n")
        self.assertEqual(self.events("worktree-reused"), [])
        self.assertEqual(self.tw("T-0002"), str(P))

    # 10 task_clones wins
    def test_task_clones_wins_over_reuse(self):
        self.pooled()
        self.set_cfg(task_clones="1")
        before = self.rows()
        self.todo(2)
        self.spawn(2)
        clone = self.wts / "G-001-T-0002"
        self.assertTrue((clone / ".git").is_dir())
        self.assertEqual(self.tw("T-0002"), str(clone))
        self.assertEqual(self.rows(), before)
        self.assertEqual(self.events("worktree-reused"), [])



if __name__ == "__main__":
    unittest.main()
