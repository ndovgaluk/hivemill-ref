"""T-1228 (G-038 SC2, F-04): `factory config --changed` lists live values that differ from DEFAULT_CONFIG and
`factory config --check` runs the set path's per-key validators over every live value (exit 2 if any is bad)."""
import sqlite3
import unittest

from harness import FactoryTestCase


class ConfigCheck(FactoryTestCase):
    def setUp(self):
        super().setUp()
        self.env.seed_agent("claude-director", "director")
        self.db_exec("DELETE FROM config")  # the harness pre-sets a few keys; start from the defaults

    def db_exec(self, sql, *args):
        con = sqlite3.connect(self.env.db_path)
        con.execute(sql, args)
        con.commit()
        con.close()

    def test_changed_fresh_home(self):
        r = self.env.run("config", "--changed", agent="claude-director")
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "no changes from defaults"), r.stderr)

    def test_changed_lists_one_key(self):
        r = self.env.run("config", "digest_hour", "9", agent="claude-director")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.env.run("config", "--changed")
        lines = r.stdout.strip().splitlines()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(lines), 1, r.stdout)
        self.assertIn("digest_hour = 9 (default: 8)", lines[0])

    def test_check_clean_home(self):
        r = self.env.run("config", "--check")
        self.assertEqual((r.returncode, r.stdout), (0, ""), r.stderr)

    def test_check_bad_stored_value(self):
        self.db_exec("INSERT INTO config(key,value) VALUES('guard_impl','bogus')")
        self.db_exec("INSERT INTO config(key,value) VALUES('task_clones','7')")
        r = self.env.run("config", "--check")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("guard_impl", r.stdout)
        self.assertIn("task_clones: task_clones must be 0 or 1, not '7'", r.stdout)  # does not stop at the first bad key

    def test_check_null_stored_value(self):
        # the schema says NOT NULL, so model a damaged DB: rebuild the table without the constraint
        self.db_exec("DROP TABLE config")
        self.db_exec("CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT)")
        self.db_exec("INSERT INTO config(key,value) VALUES('guard_impl',NULL)")
        r = self.env.run("config", "--check")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("guard_impl: guard_impl is NULL", r.stdout)
        self.assertNotIn("Traceback", r.stderr)

    def test_set_path_unchanged(self):
        r = self.env.run("config", "guard_impl", "bogus", agent="claude-director")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stderr.strip(), "factory: guard_impl must be one of python, go, shadow, not 'bogus': "
                                           "fix it with `factory config guard_impl python`")
        r = self.env.run("config", "opus_effort", "bogus", agent="claude-director")
        self.assertEqual(r.returncode, 1)  # this one has always exited 1
        r = self.env.run("config", "guard_impl", " python ", agent="claude-director")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.env.run("config", "guard_impl").stdout.strip(), "python")

    def test_flags_refuse_arguments(self):
        for args in (("--changed", "digest_hour"), ("--check", "digest_hour", "9"), ("--changed", "--check")):
            r = self.env.run("config", *args)
            self.assertEqual(r.returncode, 2, args)
            self.assertIn("usage:", r.stderr)


class WorktreeReuseConfig(FactoryTestCase):
    """G-002: worktree_reuse (0|1) and worktree_pool_max (0..50) through the real `factory config` entry point."""

    def setUp(self):
        super().setUp()
        self.env.seed_agent("claude-director", "director")
        con = sqlite3.connect(self.env.db_path)
        con.execute("DELETE FROM config")
        con.commit()
        con.close()

    def test_defaults(self):
        self.assertEqual(self.ok("config", "worktree_reuse").stdout.strip(), "0")
        self.assertEqual(self.ok("config", "worktree_pool_max").stdout.strip(), "2")

    def test_reuse_accepts_0_and_1_only(self):
        self.ok("config", "worktree_reuse", "1", agent="claude-director")
        self.assertEqual(self.ok("config", "worktree_reuse").stdout.strip(), "1")
        r = self.refused(2, "config", "worktree_reuse", "2", agent="claude-director")
        self.assertIn("worktree_reuse must be 0 or 1, not '2'", r.stderr)
        self.assertEqual(self.ok("config", "worktree_reuse").stdout.strip(), "1")  # the bad value was not stored

    def test_pool_max_range(self):
        for good in ("0", "50", "7"):
            self.ok("config", "worktree_pool_max", good, agent="claude-director")
            self.assertEqual(self.ok("config", "worktree_pool_max").stdout.strip(), good)
        for bad in ("51", "-1", "x", "", "1.5"):
            r = self.refused(2, "config", "worktree_pool_max", bad, agent="claude-director")
            self.assertIn(f"worktree_pool_max must be an integer 0..50, not {bad!r}", r.stderr)
        self.assertEqual(self.ok("config", "worktree_pool_max").stdout.strip(), "7")

    def test_check_reports_stored_bad_values(self):
        con = sqlite3.connect(self.env.db_path)
        con.execute("INSERT INTO config(key,value) VALUES('worktree_reuse','2'),('worktree_pool_max','51')")
        con.commit()
        con.close()
        r = self.refused(2, "config", "--check")
        self.assertIn("worktree_reuse: worktree_reuse must be 0 or 1, not '2'", r.stdout)
        self.assertIn("worktree_pool_max: worktree_pool_max must be an integer 0..50, not '51'", r.stdout)


if __name__ == "__main__":
    unittest.main()
