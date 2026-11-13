import hashlib
import subprocess
import unittest
from pathlib import Path

from harness import FactoryTestCase, git

URL1 = "https://github.com/zz-test/repo/pull/1"
URL2 = "https://github.com/zz-test/repo/pull/2"


class CleanTests(FactoryTestCase):
    """A real temp repo with a local bare origin; PR states come from the gh stub."""

    def setUp(self):
        super().setUp()
        e = self.env
        self.origin = e.home / "origin.git"
        self.repo = e.home / "repo"
        git("init", "-q", "--bare", "-b", "main", str(self.origin), cwd=e.home)
        git("clone", "-q", str(self.origin), str(self.repo), cwd=e.home)
        git("checkout", "-q", "-b", "main", cwd=self.repo)
        (self.repo / "README").write_text("x\n")
        git("add", "README", cwd=self.repo)
        git("commit", "-q", "-m", "init", cwd=self.repo)
        git("push", "-q", "-u", "origin", "main", cwd=self.repo)
        (e.home_dir / "worktrees").mkdir()
        e.seed_project("zz-test-proj")
        e.sql("UPDATE projects SET repo_path=? WHERE id='zz-test-proj'", (str(self.repo),))
        e.seed_goal(project="zz-test-proj")
        e.seed_agent("zz-test-cleaner", "cleaner", goal="G-001")
        e.seed_agent("zz-test-coder", "coder", goal="G-001", status="exited")

    def task(self, n=1, status="done", pr_state="MERGED", url=URL1, push=True, wt_parent=None):
        """Task T-000<n> with a worktree on factory/t-000<n> holding one commit (pushed to origin by default)."""
        e = self.env
        tid, branch = f"T-000{n}", f"factory/t-000{n}"
        wt = (wt_parent or e.home_dir / "worktrees") / f"G-001-{tid}"
        git("worktree", "add", "-q", "-b", branch, str(wt), "origin/main", cwd=self.repo)
        (wt / f"f{n}").write_text("work\n")
        git("add", f"f{n}", cwd=wt)
        git("commit", "-q", "-m", f"work {n}", cwd=wt)
        if push:
            git("push", "-q", "origin", branch, cwd=wt)
        sha = git("rev-parse", "HEAD", cwd=wt)
        e.seed_task(tid, status=status, pr_url=url if pr_state else None)
        e.sql("UPDATE tasks SET worktree=?, branch=? WHERE id=?", (str(wt), branch, tid))
        if pr_state:
            e.seed_pr(url, sha=sha, state=pr_state)
        return wt, branch, sha

    def clean(self, *args, agent="zz-test-cleaner"):
        return self.ok("clean", *args, agent=agent)

    def branches(self):
        return git("branch", "--list", "factory/*", cwd=self.repo)

    def test_clean_merged_removed(self):
        wt, branch, _ = self.task()
        p = self.clean()
        self.assertIn("removed", p.stdout)
        self.assertFalse(wt.exists())
        self.assertEqual(self.branches(), "")
        self.assertNotIn(str(wt), git("worktree", "list", cwd=self.repo))
        ev = self.env.sql("SELECT actor,detail FROM events WHERE entity='task' AND entity_id='T-0001' AND action='cleaned'")
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["actor"], "zz-test-cleaner")
        self.assertIn(branch, ev[0]["detail"])
        self.assertEqual(self.env.sql("SELECT status FROM tasks WHERE id='T-0001'")[0]["status"], "done")
        self.assertIn("1 removed", p.stdout)

    def test_clean_dry_run_noop(self):
        wt, branch, _ = self.task()
        before = git("worktree", "list", cwd=self.repo)
        p = self.clean("--dry-run")
        self.assertIn("1 would remove", p.stdout)
        self.assertTrue(wt.exists())
        self.assertIn(branch, self.branches())
        self.assertEqual(git("worktree", "list", cwd=self.repo), before)
        self.assertEqual(self.env.sql("SELECT count(*) c FROM events WHERE action='cleaned'")[0]["c"], 0)

    def test_clean_unpushed_kept(self):
        wt, branch, sha = self.task()
        (wt / "extra").write_text("more\n")
        git("add", "extra", cwd=wt)
        git("commit", "-q", "-m", "local only", cwd=wt)
        p = self.clean()
        self.assertIn("unpushed commits", p.stdout)
        self.assertTrue(wt.exists())
        self.assertIn(branch, self.branches())

    def test_clean_unpushed_on_detached_worktree_head_kept(self):
        wt, branch, sha = self.task()
        git("checkout", "-q", "--detach", cwd=wt)
        (wt / "extra").write_text("more\n")
        git("add", "extra", cwd=wt)
        git("commit", "-q", "-m", "detached local", cwd=wt)
        self.assertIn("unpushed commits", self.clean().stdout)
        self.assertTrue(wt.exists())

    def test_clean_dirty_kept(self):
        wt, branch, _ = self.task()
        (wt / "f1").write_text("edited\n")
        p = self.clean()
        self.assertIn("dirty", p.stdout)
        self.assertEqual((wt / "f1").read_text(), "edited\n")
        self.assertIn(branch, self.branches())

    def test_clean_untracked_kept_but_pycache_allowed(self):
        wt, branch, _ = self.task()
        (wt / "notes.txt").write_text("keep me\n")
        self.assertIn("untracked files: notes.txt", self.clean().stdout)
        self.assertTrue((wt / "notes.txt").exists())
        (wt / "notes.txt").unlink()
        (wt / "__pycache__").mkdir()
        (wt / "__pycache__" / "x.pyc").write_text("c")
        self.clean()
        self.assertFalse(wt.exists())

    def test_clean_live_agent_kept(self):
        wt, branch, _ = self.task()
        self.env.seed_agent("zz-test-c2", "coder", goal="G-001", task="T-0001", status="queued", pane_id="p1")
        self.assertIn("agent live", self.clean().stdout)
        self.env.sql("UPDATE agents SET status='live' WHERE name='zz-test-c2'")
        self.env.set_herdr(agents=[{"name": "zz-test-c2", "pane_id": "p1", "agent": "claude"}])
        self.assertIn("agent live", self.clean().stdout)
        self.assertTrue(wt.exists())
        self.assertIn(branch, self.branches())

    def test_clean_open_pr_kept(self):
        wt, branch, _ = self.task(pr_state="OPEN")
        self.assertIn("PR OPEN", self.clean().stdout)
        self.assertTrue(wt.exists())
        self.assertIn(branch, self.branches())

    def test_clean_active_task_kept(self):
        wt, branch, _ = self.task(status="in_review")
        self.assertIn("task in_review", self.clean().stdout)
        self.assertTrue(wt.exists())

    def test_clean_cancelled_rules(self):
        wt1, b1, _ = self.task(1, status="cancelled", pr_state="CLOSED")
        wt2, b2, _ = self.task(2, status="cancelled", pr_state=None, url=URL2, push=False)  # commit beyond base
        p = self.clean()
        self.assertFalse(wt1.exists())
        self.assertTrue(wt2.exists())
        self.assertIn("unpushed commits", p.stdout)
        # a cancelled task with no PR and nothing beyond base is removable
        git("reset", "-q", "--hard", "origin/main", cwd=wt2)
        self.clean()
        self.assertFalse(wt2.exists())

    def test_clean_outside_worktrees_untouched(self):
        outside = self.env.home / "elsewhere"
        outside.mkdir()
        wt, branch, _ = self.task(wt_parent=outside)
        p = self.clean()
        self.assertIn("outside worktrees/", p.stdout)
        self.assertTrue(wt.exists())
        self.assertIn(branch, self.branches())
        self.assertIn("outside worktrees/", self.clean("--dry-run").stdout)

    def test_clean_orphan_reported(self):
        orphan = self.env.home_dir / "worktrees" / "G-009-T-0099"
        orphan.mkdir()
        (orphan / "keep").write_text("x")
        p = self.clean()
        self.assertIn("orphan (left alone)", p.stdout)
        self.assertIn("total: 0 removed, 0 would remove, 0 skipped, 1 orphan(s)", p.stdout)  # the path cell is cut at 60 chars, so a long TMPDIR hides the name
        self.assertTrue((orphan / "keep").exists())

    def test_clean_role_refused(self):
        wt, branch, _ = self.task()
        p = self.refused(3, "clean", agent="zz-test-coder")
        self.assertIn("may not do this", p.stderr)
        self.assertTrue(wt.exists())
        self.refused(3, "clean", "--dry-run", agent="zz-test-coder")

    def test_clean_director_allowed(self):
        self.env.seed_agent("zz-test-director", "director")
        self.task()
        self.clean("--dry-run", agent="zz-test-director")

    def test_clean_survives_gh_failure_and_missing_repo(self):
        wt, branch, _ = self.task()
        self.env.set_gh(prs={})
        p = self.clean()
        self.assertIn("PR lookup failed", p.stdout)
        self.assertTrue(wt.exists())
        self.env.sql("UPDATE projects SET repo_path=NULL")
        self.assertIn("no project repo", self.clean().stdout)

    def test_clean_rerun_is_noop(self):
        self.task()
        self.assertIn("1 removed", self.clean().stdout)
        n = len(self.env.sql("SELECT 1 FROM events WHERE action='cleaned'"))
        p = self.clean()
        self.assertIn("0 removed", p.stdout)
        self.assertIn("nothing to remove", p.stdout)
        self.assertEqual(len(self.env.sql("SELECT 1 FROM events WHERE action='cleaned'")), n)
        self.assertIn("0 would remove", self.clean("--dry-run").stdout)

    def test_clean_nothing_to_remove_skips_gh(self):
        wt, branch, _ = self.task()
        git("worktree", "remove", "--force", str(wt), cwd=self.repo)
        git("branch", "-D", branch, cwd=self.repo)
        before = len(self.env.calls("gh"))
        p = self.clean()
        self.assertIn("nothing to remove", p.stdout)
        self.assertIn("0 removed", p.stdout)
        self.assertEqual(len(self.env.calls("gh")), before)
        self.assertEqual(self.env.sql("SELECT 1 FROM events WHERE action='cleaned'"), [])

    def test_clean_partial_branch_delete_failure_reported(self):
        wt, branch, _ = self.task()
        (self.repo / ".git" / "refs" / "heads" / "factory" / "t-0001.lock").write_text("")
        p = self.clean()
        self.assertFalse(wt.exists())
        self.assertIn(branch, self.branches())
        self.assertIn("removed worktree; branch delete failed", p.stdout)
        self.assertIn("1 removed", p.stdout)
        ev = self.env.sql("SELECT detail FROM events WHERE entity='task' AND entity_id='T-0001' AND action='cleaned'")
        self.assertEqual(len(ev), 1)
        self.assertIn(str(wt), ev[0]["detail"])
        self.assertNotIn(branch, ev[0]["detail"])

    def set_cwd(self, name, cwd, status="live", task=None):
        self.env.seed_agent(name, "coder", goal="G-001", task=task, status=status)
        self.env.sql("UPDATE agents SET cwd=? WHERE name=?", (str(cwd), name))

    def test_clean_protects_cwd_of_live_agent_without_task(self):
        wt, branch, _ = self.task()
        self.set_cwd("zz-test-lead", wt / "sub")
        p = self.clean()
        self.assertIn("protected: cwd of agent zz-test-lead", p.stdout)
        self.assertTrue(wt.exists())
        self.assertIn(branch, self.branches())

    def test_clean_protects_cwd_of_done_agent(self):
        wt, branch, _ = self.task()
        self.set_cwd("zz-test-fin", wt, status="done", task="T-0001")
        self.assertIn("protected: cwd of agent zz-test-fin", self.clean().stdout)
        self.assertTrue(wt.exists())
        self.env.sql("UPDATE agents SET status='exited' WHERE name='zz-test-fin'")
        self.clean()
        self.assertFalse(wt.exists())

    def test_clean_protects_stopped_worktree(self):
        wt, branch, _ = self.task()
        self.set_cwd("zz-test-fin", wt, status="stopped", task="T-0001")  # force-stopped: the successor reuses it
        self.assertIn("protected: cwd of agent zz-test-fin", self.clean().stdout)
        self.assertTrue(wt.exists())
        self.env.sql("UPDATE agents SET status='exited' WHERE name='zz-test-fin'")
        self.clean()
        self.assertFalse(wt.exists())

    def test_clean_protects_cwd_via_symlink_path(self):
        wt, branch, _ = self.task()
        link = self.env.home / "link"
        link.symlink_to(self.env.home_dir / "worktrees")
        self.set_cwd("zz-test-sym", f"{link}/{wt.name}/")
        self.assertIn("protected: cwd of agent zz-test-sym", self.clean().stdout)
        self.assertTrue(wt.exists())

    def test_clean_protects_pane_cwd_from_herdr(self):
        wt, branch, _ = self.task()
        pane = {"pane_id": "p9", "tab_id": "t9", "workspace_id": "w9"}
        self.env.set_herdr(panes=[{**pane, "cwd": "/", "foreground_cwd": str(wt / "src")}])
        self.assertIn("protected: cwd of a live pane", self.clean().stdout)
        self.assertTrue(wt.exists())
        # a pane in a parent directory of the worktree does not hold it
        self.env.set_herdr(panes=[{**pane, "cwd": str(self.env.home_dir)}])
        self.clean()
        self.assertFalse(wt.exists())

    def test_clean_fails_closed_when_herdr_unreachable(self):
        wt, branch, _ = self.task()
        self.env.set_herdr(fail=True)
        p = self.refused(4, "clean", agent="zz-test-cleaner")
        self.assertIn("cannot verify live panes", p.stderr)
        self.refused(4, "clean", "--dry-run", agent="zz-test-cleaner")
        self.assertTrue(wt.exists())
        self.assertIn(branch, self.branches())

    def test_clean_dry_run_shows_protection_reason(self):
        wt, branch, _ = self.task()
        self.set_cwd("zz-test-lead", wt)
        p = self.clean("--dry-run")
        self.assertIn("protected: cwd of agent zz-test-lead", p.stdout)
        self.assertIn("0 would remove", p.stdout)

    def test_clean_relative_path_rejected(self):
        wt, branch, _ = self.task()
        self.env.sql("UPDATE tasks SET worktree='worktrees/x' WHERE id='T-0001'")
        p = self.clean()
        self.assertIn("recorded path not absolute", p.stdout)
        self.assertTrue(wt.exists())
        self.assertIn(branch, self.branches())

    # -- T-0332: live agent = pane still belongs to it; closed PR landed on main -----------------------------------
    def live_agent(self, name="zz-test-c2", pane="p1", task="T-0001", started="2026-01-01T00:00:00+00:00"):
        self.env.seed_agent(name, "coder", goal="G-001", task=task, status="live", started=started, pane_id=pane)

    def list_agents(self, *agents):
        self.env.set_herdr(agents=[{"name": n, "pane_id": p, "agent": "claude"} for n, p in agents])

    def land(self, branch, n=1, squash=True):
        """Put the branch's work on origin/main (a squash commit, or the branch itself) and record the 'merged' event."""
        git("checkout", "-q", "main", cwd=self.repo)
        git("pull", "-q", "origin", "main", cwd=self.repo)
        if squash:
            git("checkout", "-q", f"origin/{branch}", "--", f"f{n}", cwd=self.repo)
            git("commit", "-q", "-m", f"squash ({n})", cwd=self.repo)
        else:
            git("merge", "-q", "--ff-only", f"origin/{branch}", cwd=self.repo)
        git("push", "-q", "origin", "main", cwd=self.repo)
        main = git("rev-parse", "HEAD", cwd=self.repo)
        self.env.sql("INSERT INTO events(ts,actor,entity,entity_id,action,detail) VALUES('t','judge','task',?,'merged',?)",
                     (f"T-000{n}", f"@{main[:8]}"))
        return main

    def test_reused_pane_of_ended_agent_does_not_keep_worktree(self):
        self.task()
        self.live_agent(pane="p1")  # stale 'live' row; p1 now belongs to another agent
        self.list_agents(("zz-test-other", "p1"))
        p = self.clean("--dry-run")
        self.assertIn("1 would remove", p.stdout)
        self.assertNotIn("agent live", p.stdout)

    def test_live_agent_with_its_own_pane_keeps_worktree(self):
        wt, _, _ = self.task()
        self.live_agent(pane="p1")
        self.list_agents(("zz-test-c2", "p1"))
        self.assertIn("agent live", self.clean().stdout)
        self.assertTrue(wt.exists())

    def test_live_row_missing_from_pane_list_past_grace_is_not_live(self):
        self.task()
        self.live_agent(pane="p1")
        self.list_agents()
        self.assertIn("1 would remove", self.clean("--dry-run").stdout)

    def test_live_row_with_live_pane_elsewhere_keeps_worktree_until_pane_gone(self):
        """T-0923 (T-0339): done task, MERGED PR, live agent row missing from the agent list, its pane alive but with its
        cwd outside the worktree: kept; removed once the pane is gone."""
        wt, _, _ = self.task()
        self.live_agent(pane="p1")
        self.list_agents()
        self.env.set_herdr(panes=[{"pane_id": "p1", "workspace_id": "w1", "cwd": str(self.env.home)}])
        self.assertIn("agent live", self.clean().stdout)
        self.assertTrue(wt.exists())
        self.env.set_herdr(panes=[])
        self.assertIn("1 removed", self.clean().stdout)
        self.assertFalse(wt.exists())

    def test_fresh_live_row_not_yet_listed_is_kept(self):
        self.task()
        now = self.env.sql("SELECT strftime('%Y-%m-%dT%H:%M:%S+00:00','now') t")[0]["t"]
        self.live_agent(pane="p1", started=now)
        self.list_agents()
        self.assertIn("agent live", self.clean("--dry-run").stdout)

    def test_queued_agent_keeps_worktree(self):
        self.task()
        self.env.seed_agent("zz-test-c3", "coder", goal="G-001", task="T-0001", status="queued")
        self.list_agents()
        self.assertIn("agent live", self.clean("--dry-run").stdout)

    def test_closed_pr_landed_squash_and_task_done_removable(self):
        wt, branch, _ = self.task(pr_state="CLOSED")
        self.land(branch)
        self.assertIn("1 would remove", self.clean("--dry-run").stdout)
        self.assertTrue(wt.exists())  # dry run
        self.assertIn("1 removed", self.clean().stdout)
        self.assertFalse(wt.exists())

    def test_closed_pr_head_ancestor_of_main_removable(self):
        _, branch, _ = self.task(pr_state="CLOSED")
        self.land(branch, squash=False)
        self.assertIn("1 would remove", self.clean("--dry-run").stdout)

    def test_closed_pr_work_not_on_main_kept(self):
        wt, _, _ = self.task(pr_state="CLOSED")
        self.assertIn("PR CLOSED", self.clean("--dry-run").stdout)
        self.assertTrue(wt.exists())

    def test_closed_pr_merged_event_but_work_missing_from_main_kept(self):
        self.task(pr_state="CLOSED")
        main = git("rev-parse", "origin/main", cwd=self.repo)  # a real main commit that does not hold f1
        self.env.sql("INSERT INTO events(ts,actor,entity,entity_id,action,detail) VALUES('t','judge','task','T-0001','merged',?)",
                     (f"@{main[:8]}",))
        self.assertIn("PR CLOSED", self.clean("--dry-run").stdout)

    def test_closed_pr_landed_but_task_not_done_kept(self):
        _, branch, _ = self.task(status="in_review", pr_state="CLOSED")
        self.land(branch)
        self.assertIn("task in_review", self.clean("--dry-run").stdout)

    def test_closed_pr_landed_but_dirty_kept(self):
        wt, branch, _ = self.task(pr_state="CLOSED")
        self.land(branch)
        (wt / "f1").write_text("changed\n")
        self.assertIn("dirty", self.clean("--dry-run").stdout)
        self.assertTrue(wt.exists())

    def test_doubt_unknown_merged_commit_keeps_worktree(self):
        wt, branch, _ = self.task(pr_state="CLOSED")
        self.land(branch)
        self.env.sql("UPDATE events SET detail='@deadbeef' WHERE action='merged'")  # not a commit here
        self.assertIn("PR CLOSED", self.clean("--dry-run").stdout)
        self.assertTrue(wt.exists())

    def test_doubt_agent_list_unavailable_keeps_live_row(self):
        wt, _, _ = self.task()
        self.live_agent(pane="p1")
        self.env.set_herdr(agents=None)  # the stub's `agent list` then answers without usable agents
        p = self.clean("--dry-run")
        self.assertTrue(wt.exists())
        self.assertIn("agent live", p.stdout)

    def pane_at(self, pane_id, wt):
        self.env.set_herdr(panes=[{"pane_id": pane_id, "tab_id": "t9", "workspace_id": "w9", "cwd": str(wt), "foreground_cwd": str(wt)}])

    def ended_agent(self, name, pane, wt, task="T-0001", status="exited"):
        self.env.seed_agent(name, "coder", goal="G-001", task=task, status=status, pane_id=pane)
        self.env.sql("UPDATE agents SET cwd=? WHERE name=?", (str(wt), name))

    def test_three_reported_cases_removable_in_one_dry_run(self):
        w1, _, _ = self.task(1)
        w2, _, _ = self.task(2, url=URL2)
        self.ended_agent("zz-test-a1", "p1", w1)  # exited, but its pane id is still listed in the worktree
        self.ended_agent("zz-test-a2", "p2", w2, task="T-0002")
        self.env.set_herdr(panes=[{"pane_id": p, "tab_id": "t9", "workspace_id": "w9", "cwd": str(w), "foreground_cwd": str(w)}
                                  for p, w in (("p1", w1), ("p2", w2))])
        self.list_agents(("zz-test-n1", "p7"))  # p1/p2 are leftover panes: no listed agent sits on them
        w3, b3, _ = self.task(3, pr_state="CLOSED", url="https://github.com/zz-test/repo/pull/3")
        self.land(b3, n=3)
        self.assertIn("3 would remove", self.clean("--dry-run").stdout)
        for w in (w1, w2, w3):
            self.assertTrue(w.exists())

    def test_exited_agent_leftover_pane_with_no_listed_agent_does_not_protect_by_pane_cwd(self):
        wt, _, _ = self.task()
        self.ended_agent("zz-test-gone", "p1", wt / "sub", status="exited")
        self.env.sql("UPDATE agents SET cwd=NULL")  # only the pane cwd is left to hold it
        self.pane_at("p1", wt)
        self.list_agents(("zz-test-other", "p7"))  # leftover pane: nothing listed on p1
        p = self.clean("--dry-run")
        self.assertNotIn("protected", p.stdout)
        self.assertIn("1 would remove", p.stdout)

    def test_P1_listed_unknown_agent_without_db_row_holds_pane_cwd(self):
        wt, _, _ = self.task()
        self.ended_agent("zz-test-gone", "p1", wt / "sub", status="exited")
        self.env.sql("UPDATE agents SET cwd=NULL")
        self.pane_at("p1", wt)
        self.list_agents(("zz-test-stranger", "p1"))  # listed on p1, unknown to the DB
        self.assertIn("protected: cwd of a live pane", self.clean("--dry-run").stdout)
        self.assertTrue(wt.exists())

    def test_P2_listed_starting_row_without_pane_id_holds_pane_cwd(self):
        wt, _, _ = self.task()
        self.ended_agent("zz-test-gone", "p1", wt / "sub", status="exited")
        self.env.seed_agent("zz-test-new", "coder", goal="G-001", task="T-0002", status="starting")  # pane_id NULL
        self.env.sql("UPDATE agents SET cwd=NULL")
        self.pane_at("p1", wt)
        self.list_agents(("zz-test-new", "p1"))
        self.assertIn("protected: cwd of a live pane", self.clean("--dry-run").stdout)
        self.assertTrue(wt.exists())

    def test_stale_live_row_with_recorded_cwd_does_not_protect(self):
        wt, _, _ = self.task()
        self.ended_agent("zz-test-c2", "p1", wt, status="live")  # spawn recorded cwd=wt; p1 now belongs to another agent
        self.list_agents(("zz-test-other", "p1"))
        p = self.clean("--dry-run")
        self.assertNotIn("protected", p.stdout)
        self.assertIn("1 would remove", p.stdout)

    def test_pane_cwd_kept_when_owner_unknown_or_running(self):
        wt, _, _ = self.task()
        self.pane_at("p9", wt)  # no agent row owns p9
        self.assertIn("protected: cwd of a live pane", self.clean("--dry-run").stdout)
        self.live_agent("zz-test-c2", "p9", task="T-0002")  # a running agent of another task owns the pane
        self.list_agents(("zz-test-c2", "p9"))
        self.assertIn("protected: cwd of a live pane", self.clean("--dry-run").stdout)

    def test_live_row_with_recorded_cwd_kept_when_listed_or_agents_unknown(self):
        wt, _, _ = self.task()
        self.env.seed_agent("zz-test-lead", "lead", goal="G-001", status="live", pane_id="p1")
        self.env.sql("UPDATE agents SET cwd=? WHERE name='zz-test-lead'", (str(wt),))
        self.list_agents(("zz-test-lead", "p1"))
        self.assertIn("protected: cwd of agent zz-test-lead", self.clean("--dry-run").stdout)
        self.env.set_herdr(agents=None)
        self.assertIn("protected: cwd of agent zz-test-lead", self.clean("--dry-run").stdout)

    def test_live_row_listed_by_name_under_another_pane_is_still_live(self):
        wt, _, _ = self.task()
        self.live_agent(pane="p1")
        self.list_agents(("zz-test-c2", "p7"), ("zz-test-other", "p1"))
        self.assertIn("agent live", self.clean("--dry-run").stdout)
        self.assertTrue(wt.exists())


class CleanPoolTests(CleanTests):
    """G-002 B: `factory clean` with worktree_reuse pools merged worktrees, trims to worktree_pool_max, never removes a claim."""

    def cfg(self, reuse="1", pool_max="2"):
        for k, v in (("worktree_reuse", reuse), ("worktree_pool_max", pool_max)):
            self.env.sql("INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, v))

    def rows(self):
        return self.env.sql("SELECT * FROM worktree_pool ORDER BY path")

    def events(self, action):
        return self.env.sql("SELECT detail FROM events WHERE action=?", (action,))

    def wts(self):
        return self.env.home_dir / "worktrees"

    def pool_wt(self, name, state="free", task=None, released="2026-01-01T00:00:00+00:00", project="zz-test-proj", repo=None):
        """A real detached linked worktree at origin/main under worktrees/, with a worktree_pool row."""
        repo = repo or self.repo
        wt = self.wts().resolve() / name
        git("worktree", "add", "-q", "--detach", str(wt), "origin/main", cwd=repo)
        self.env.sql("INSERT INTO worktree_pool(path,project_id,state,task_id,reset_ok,claimed_at,released_at) VALUES(?,?,?,?,1,?,?)",
                     (str(wt), project, state, task, None if state == "free" else released, released))
        return wt

    def snap(self, wt):
        admin = Path(git("rev-parse", "--absolute-git-dir", cwd=wt))
        return {n: hashlib.sha256((admin / n).read_bytes()).hexdigest() for n in ("HEAD", "index") if (admin / n).exists()}

    def norm(self, out, *wts):
        out = out.replace(str(self.env.home_dir), "<HOME>")
        return "\n".join(" ".join(l.split()) for l in out.splitlines())

    def symbolic_rc(self, wt):
        return subprocess.run(["git", "symbolic-ref", "-q", "HEAD"], cwd=wt, capture_output=True, text=True).returncode

    # 1 flag off: today's output, pinned
    def test_flag_off_output_pinned(self):
        wt, _, _ = self.task()
        out = self.norm(self.clean("--dry-run").stdout)
        self.assertEqual(out, "\n".join([
            "TASK WORKTREE BRANCH ACTION REASON",
            "T-0001 <HOME>/worktrees/G-001-T-0001 factory/t-0001 would remove merged and clean",
            "total: 0 removed, 1 would remove, 0 skipped, 0 orphan(s), 0 sandbox dir(s) kept [dry run]"]))
        out = self.norm(self.clean().stdout)
        self.assertEqual(out, "\n".join([
            "TASK WORKTREE BRANCH ACTION REASON",
            "T-0001 <HOME>/worktrees/G-001-T-0001 factory/t-0001 removed merged and clean",
            "total: 1 removed, 0 would remove, 0 skipped, 0 orphan(s), 0 sandbox dir(s) kept"]))
        self.assertEqual(self.rows(), [])

    def test_flag_off_unpushed_pinned(self):
        wt, _, _ = self.task()
        (wt / "extra").write_text("more\n")
        git("add", "extra", cwd=wt)
        git("commit", "-q", "-m", "local only", cwd=wt)
        out = self.norm(self.clean().stdout)
        self.assertEqual(out, "\n".join([
            "TASK WORKTREE BRANCH ACTION REASON",
            "T-0001 <HOME>/worktrees/G-001-T-0001 factory/t-0001 skip unpushed commits",
            "total: 0 removed, 0 would remove, 1 skipped, 0 orphan(s), 0 sandbox dir(s) kept"]))
        self.assertEqual(self.rows(), [])

    # 2 flag off never touches the pool helper
    def test_flag_off_ignores_forged_gitdir(self):
        a, _, _ = self.task(1)
        s, _, _ = self.task(2, status="in_progress", pr_state=None)
        (a / "stray").write_text("x\n")
        admin_s = Path(git("rev-parse", "--absolute-git-dir", cwd=s))
        (a / ".git").write_text(f"gitdir: {admin_s}\n")
        p = self.clean()
        self.assertNotIn("gitdir mismatch", p.stdout)
        self.assertEqual(self.events("worktree-gitdir-mismatch"), [])
        self.assertEqual(self.rows(), [])
        self.assertTrue(s.exists())

    # 3 release
    def test_release_to_pool(self):
        self.cfg()
        wt, branch, _ = self.task()
        (wt / ".gitignore").write_text("node_modules/\n")
        git("add", ".gitignore", cwd=wt)
        git("commit", "-q", "-m", "ignore", cwd=wt)
        git("push", "-q", "origin", branch, cwd=wt)
        sha = git("rev-parse", "HEAD", cwd=wt)
        self.env.seed_pr(URL1, sha=sha, state="MERGED")
        (wt / "node_modules").mkdir()
        (wt / "node_modules" / "x").write_text("cache\n")
        p = self.clean()
        self.assertIn("pooled", p.stdout)
        self.assertIn("released to pool", p.stdout)
        self.assertIn(", 1 pooled", p.stdout)
        self.assertTrue(wt.exists())
        self.assertEqual(self.symbolic_rc(wt), 1)
        self.assertEqual(git("rev-parse", "HEAD", cwd=wt), git("rev-parse", "origin/main", cwd=self.repo))
        self.assertEqual(self.branches(), "")
        self.assertIsNone(self.env.sql("SELECT worktree FROM tasks WHERE id='T-0001'")[0]["worktree"])
        rows = self.rows()
        self.assertEqual([(r["path"], r["state"], r["task_id"]) for r in rows], [(str(wt.resolve()), "free", None)])
        self.assertEqual(len(self.events("worktree-pooled")), 1)
        self.assertTrue((wt / "node_modules" / "x").exists())
        self.assertNotIn("orphan (left alone)", p.stdout)  # 10: a pooled dir is known

    # 4 cap, per project
    def test_cap_and_per_project(self):
        self.cfg(pool_max="2")
        wts = [self.task(n, url=f"https://github.com/zz-test/repo/pull/{n}")[0] for n in range(1, 5)]
        origin2, repo2 = self.env.home / "origin2.git", self.env.home / "repo2"
        git("init", "-q", "--bare", "-b", "main", str(origin2), cwd=self.env.home)
        git("clone", "-q", str(origin2), str(repo2), cwd=self.env.home)
        git("checkout", "-q", "-b", "main", cwd=repo2)
        (repo2 / "R").write_text("y\n")
        git("add", "R", cwd=repo2)
        git("commit", "-q", "-m", "init", cwd=repo2)
        git("push", "-q", "-u", "origin", "main", cwd=repo2)
        self.env.seed_project("zz-proj2")
        self.env.sql("UPDATE projects SET repo_path=? WHERE id='zz-proj2'", (str(repo2),))
        self.env.seed_goal("G-002", project="zz-proj2")
        other = []
        for n in (5, 6, 7):
            wt = self.wts() / f"G-002-T-000{n}"
            git("worktree", "add", "-q", "-b", f"factory/t-000{n}", str(wt), "origin/main", cwd=repo2)
            url = f"https://github.com/zz-test/repo/pull/{n}"
            self.env.seed_task(f"T-000{n}", goal="G-002", status="done", pr_url=url)
            self.env.sql("UPDATE tasks SET worktree=?, branch=? WHERE id=?", (str(wt), f"factory/t-000{n}", f"T-000{n}"))
            self.env.seed_pr(url, sha=git("rev-parse", "HEAD", cwd=wt), state="MERGED")
            other.append(wt)
        p = self.clean()
        by = {}
        for r in self.rows():
            by.setdefault(r["project_id"], []).append(r["path"])
        self.assertEqual({k: len(v) for k, v in by.items()}, {"zz-test-proj": 2, "zz-proj2": 2})
        self.assertEqual(sum(w.exists() for w in wts), 2)
        self.assertEqual(sum(w.exists() for w in other), 2)
        self.assertEqual(len(git("worktree", "list", cwd=self.repo).splitlines()), 3)
        self.assertIn(", 4 pooled", p.stdout)
        self.assertEqual(sum(1 for l in p.stdout.splitlines() if " ".join(l.split()).endswith("removed merged and clean")), 3)

    def test_cap_zero_removes_all(self):
        self.cfg(pool_max="0")
        wt, _, _ = self.task()
        p = self.clean()
        self.assertFalse(wt.exists())
        self.assertIn("1 removed", p.stdout)
        self.assertNotIn("pooled", p.stdout)
        self.assertEqual(self.rows(), [])

    # 5 claimed never removed, oldest free trimmed first
    def test_claimed_never_removed_and_oldest_trimmed(self):
        self.cfg(pool_max="1")
        f = [self.pool_wt(f"pool-f{i}", released=f"2026-01-0{i}T00:00:00+00:00") for i in (1, 2, 3)]
        c = []
        for i in (1, 2):
            self.env.seed_task(f"T-009{i}", status="in_progress", pr_url=None)
            wt = self.pool_wt(f"pool-c{i}", state="claimed", task=f"T-009{i}")
            self.env.sql("UPDATE tasks SET worktree=? WHERE id=?", (str(wt), f"T-009{i}"))
            c.append(wt)
        before = [self.snap(w) for w in c]
        p = self.clean()
        self.assertEqual([self.snap(w) for w in c], before)
        self.assertTrue(all(w.exists() for w in c))
        self.assertEqual([r["state"] for r in self.rows() if r["state"] == "claimed"], ["claimed", "claimed"])
        free = [r["path"] for r in self.rows() if r["state"] == "free"]
        self.assertEqual(free, [str(f[2])])
        self.assertFalse(f[0].exists() or f[1].exists())
        self.assertEqual(len(self.events("worktree-pool-trimmed")), 2)
        self.assertEqual(p.stdout.count("pool over cap"), 2)

    # 6 safety refusals stay
    def test_safety_refusals_not_pooled(self):
        self.cfg()
        wt, _, _ = self.task(1)
        (wt / "stray").write_text("x\n")
        wt2, _, _ = self.task(2, url=URL2)
        (wt2 / "extra").write_text("more\n")
        git("add", "extra", cwd=wt2)
        git("commit", "-q", "-m", "local only", cwd=wt2)
        p = self.clean()
        self.assertIn("untracked files: stray", p.stdout)
        self.assertIn("unpushed commits", p.stdout)
        self.assertEqual(self.rows(), [])
        wt3, _, _ = self.task(3, url="https://github.com/zz-test/repo/pull/3")
        self.pane_at("p1", wt3)
        p = self.clean()
        self.assertIn("protected: cwd of a live pane", p.stdout)
        self.assertEqual(self.rows(), [])
        self.assertTrue(wt.exists() and wt2.exists() and wt3.exists())

    # 7 forged / symlinked pool rows
    def test_forged_and_symlinked_pool_rows_kept(self):
        self.cfg(pool_max="0")
        self.env.seed_task("T-0050", status="in_progress", pr_url=None)
        s = self.pool_wt("sibling", state="claimed", task="T-0050")
        self.env.sql("UPDATE tasks SET worktree=? WHERE id='T-0050'", (str(s),))
        admin_s = Path(git("rev-parse", "--absolute-git-dir", cwd=s))
        link = self.wts().resolve() / "linked"
        link.symlink_to(s)
        forged = self.wts().resolve() / "forged"
        forged.mkdir()
        (forged / ".git").write_text(f"gitdir: {admin_s}\n")
        for p_ in (link, forged):
            self.env.sql("INSERT INTO worktree_pool(path,project_id,state,task_id,reset_ok,claimed_at,released_at) "
                         "VALUES(?,?,'free',NULL,0,NULL,'2026-01-01T00:00:00+00:00')", (str(p_), "zz-test-proj"))
        before = self.snap(s)
        p = self.clean()
        self.assertEqual(p.stdout.count("kept: gitdir mismatch"), 2)
        self.assertTrue(s.exists())
        self.assertEqual(self.snap(s), before)
        self.assertEqual(len(self.events("worktree-gitdir-mismatch")), 2)
        msgs = lambda: self.env.sql("SELECT count(*) c FROM messages WHERE subject LIKE 'worktree gitdir mismatch%'")[0]["c"]
        self.assertEqual(msgs(), 2)
        self.clean()
        self.clean("--dry-run")
        self.assertEqual(len(self.events("worktree-gitdir-mismatch")), 2)
        self.assertEqual(msgs(), 2)
        self.assertEqual(self.snap(s), before)
        self.assertEqual(len(self.rows()), 3)

    # 8 stale claims
    def test_stale_claims(self):
        self.cfg(pool_max="5")
        self.env.seed_task("T-0060", status="done", pr_url=None)
        clean_wt = self.pool_wt("stale-clean", state="claimed", task="T-0060")
        self.env.seed_task("T-0061", status="done", pr_url=None)
        dirty = self.pool_wt("stale-dirty", state="claimed", task="T-0061")
        (dirty / "README").write_text("edited\n")
        self.env.seed_task("T-0062", status="cancelled", pr_url=None)
        gone = self.pool_wt("stale-gone", state="claimed", task="T-0062")
        git("worktree", "remove", "--force", str(gone), cwd=self.repo)
        self.env.seed_task("T-0063", status="in_progress", pr_url=None)
        active = self.pool_wt("active", state="claimed", task="T-0063")
        self.env.sql("UPDATE tasks SET worktree=? WHERE id='T-0063'", (str(active),))
        before = self.snap(active)
        p = self.clean()
        st = {r["path"]: r for r in self.rows()}
        self.assertEqual(st[str(clean_wt)]["state"], "free")
        self.assertIsNone(st[str(clean_wt)]["task_id"])
        self.assertEqual(st[str(dirty)]["state"], "claimed")
        self.assertTrue(dirty.exists())
        self.assertNotIn(str(gone), st)
        self.assertIn("stale claim, dir gone", p.stdout)
        self.assertIn("dirty", p.stdout)
        self.assertEqual(st[str(active)]["state"], "claimed")
        self.assertEqual(self.snap(active), before)

    def test_stale_claim_trimmed_under_cap(self):
        self.cfg(pool_max="0")
        self.env.seed_task("T-0060", status="done", pr_url=None)
        wt = self.pool_wt("stale-clean", state="claimed", task="T-0060")
        self.clean()
        self.assertFalse(wt.exists())
        self.assertEqual(self.rows(), [])

    # M513: a dir whose admin dir holds config.worktree is never pooled
    def admin_of(self, wt):
        return Path(git("rev-parse", "--absolute-git-dir", cwd=wt))

    def row_for(self, out, task):
        return [" ".join(l.split()) for l in out.splitlines() if l.startswith(task)]

    def test_forbidden_config_worktree_not_pooled(self):
        self.cfg()
        wt, branch, _ = self.task()
        marker = self.env.home / "marker"
        script = self.env.home / "mon.sh"
        script.write_text(f"#!/bin/sh\ntouch {marker}\n")
        script.chmod(0o755)
        (self.admin_of(wt) / "config.worktree").write_text(f"[core]\n\tfsmonitor = {script}\n")
        for args in (("--dry-run",), ()):
            p = self.clean(*args)
            rows = self.row_for(p.stdout, "T-0001")
            self.assertEqual(len(rows), 1, p.stdout)
            self.assertIn(" skip git config refused", rows[0])
            self.assertEqual(self.env.sql("SELECT count(*) c FROM worktree_pool")[0]["c"], 0)
            self.assertTrue(wt.is_dir())
            self.assertIn(branch, self.branches())
            self.assertFalse(marker.exists(), "core.fsmonitor command ran")

    def test_config_worktree_with_allowed_keys_not_pooled(self):
        self.cfg()
        wt1, branch, _ = self.task(1)
        wt2, _, _ = self.task(2, url=URL2)
        before = self.env.sql("SELECT worktree FROM tasks WHERE id='T-0001'")[0]["worktree"]
        (self.admin_of(wt1) / "config.worktree").write_text("[user]\n\tname = previous-task\n")
        for args in (("--dry-run",), ()):
            p = self.clean(*args)
            rows = self.row_for(p.stdout, "T-0001")
            self.assertEqual(len(rows), 1, p.stdout)
            self.assertTrue(rows[0].endswith(" skip kept: has config.worktree"), rows[0])
            self.assertEqual([r["path"] for r in self.rows()], [] if args else [str(wt2.resolve())])
            self.assertTrue(wt1.is_dir())
            self.assertEqual(git("symbolic-ref", "HEAD", cwd=wt1), "refs/heads/factory/t-0001")
            self.assertEqual(self.env.sql("SELECT worktree FROM tasks WHERE id='T-0001'")[0]["worktree"], before)
            self.assertEqual(self.events("worktree-pooled") and [e for e in self.events("worktree-pooled") if "T-0001" in e["detail"]], [])
        self.assertEqual([r["state"] for r in self.rows()], ["free"])
        self.assertIn(branch, self.branches())

    def test_stale_claim_with_config_worktree_stays_claimed(self):
        self.cfg(pool_max="5")
        self.env.seed_task("T-0009", status="done", pr_url=None)
        wt = self.pool_wt("stale-cw", state="claimed", task="T-0009")
        (self.admin_of(wt) / "config.worktree").write_text("[user]\n\tname = previous-task\n")
        for args in (("--dry-run",), ()):
            p = self.clean(*args)
            self.assertIn("kept: has config.worktree", p.stdout)
            rows = self.rows()
            self.assertEqual([(r["state"], r["task_id"]) for r in rows], [("claimed", "T-0009")])
            self.assertTrue(wt.exists())

    # 9 dry run
    def test_dry_run_changes_nothing(self):
        self.cfg(pool_max="2")
        wts = [self.task(n, url=f"https://github.com/zz-test/repo/pull/{n}")[0] for n in range(1, 4)]
        old = self.pool_wt("old-free")
        self.cfg(pool_max="2")
        self.env.sql("UPDATE worktree_pool SET released_at='2025-01-01T00:00:00+00:00'")
        tasks_before = self.env.sql("SELECT id, worktree, branch, status FROM tasks ORDER BY id")
        rows_before = [tuple(r) for r in self.rows()]
        ev = self.env.sql("SELECT count(*) c FROM events")[0]["c"]
        msg = self.env.sql("SELECT count(*) c FROM messages")[0]["c"]
        p = self.clean("--dry-run")
        self.assertIn("would pool", p.stdout)
        self.assertIn("would remove", p.stdout)
        self.assertEqual([tuple(r) for r in self.rows()], rows_before)
        self.assertEqual(self.env.sql("SELECT id, worktree, branch, status FROM tasks ORDER BY id"), tasks_before)
        self.assertTrue(all(w.exists() for w in wts) and old.exists())
        self.assertEqual(len(self.branches().splitlines()), 3)
        self.assertEqual(self.env.sql("SELECT count(*) c FROM events")[0]["c"], ev)
        self.assertEqual(self.env.sql("SELECT count(*) c FROM messages")[0]["c"], msg)
        self.assertIn("1 pooled", p.stdout)
        self.assertIn("[dry run]", p.stdout)

    # 12 clones are never pooled
    def test_clone_removed_not_pooled(self):
        self.cfg()
        e = self.env
        wt, branch = self.wts() / "G-001-T-0001", "factory/t-0001"
        git("-c", "protocol.file.allow=always", "clone", "-q", "--shared", "--no-checkout", str(self.repo), str(wt), cwd=e.home)
        git("remote", "set-url", "origin", str(self.origin), cwd=wt)
        git("fetch", "-q", "origin", cwd=wt)
        git("checkout", "-q", "-b", branch, "origin/main", cwd=wt)
        sha = git("rev-parse", "HEAD", cwd=wt)
        e.seed_task("T-0001", status="done", pr_url=URL1)
        e.sql("UPDATE tasks SET worktree=?, branch=? WHERE id='T-0001'", (str(wt), branch))
        e.seed_pr(URL1, sha=sha, state="MERGED")
        p = self.clean()
        self.assertFalse(wt.exists())
        self.assertIn("1 removed", p.stdout)
        self.assertEqual(self.rows(), [])

    def test_claimed_row_of_released_task_turns_free(self):
        self.cfg()
        wt, branch, sha = self.task()
        self.env.sql("INSERT INTO worktree_pool(path,project_id,state,task_id,reset_ok,claimed_at,released_at) "
                     "VALUES(?,?,'claimed','T-0001',1,'2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00')", (str(wt.resolve()), "zz-test-proj"))
        self.clean()
        r = self.rows()
        self.assertEqual([(x["state"], x["task_id"]) for x in r], [("free", None)])
        self.cfg(pool_max="0")
        self.clean()
        self.assertFalse(wt.exists())
        self.assertEqual(self.rows(), [])

    # T-0018 item 1: a trim-only run says so
    def test_trim_only_summary_suffix(self):
        self.cfg(pool_max="0")
        for i in (1, 2):
            self.pool_wt(f"pool-f{i}", released=f"2026-01-0{i}T00:00:00+00:00")
        p = self.clean("--dry-run")
        self.assertIn("total: 0 removed, 2 would remove, 0 skipped, 0 orphan(s), 0 sandbox dir(s) kept, 0 pooled, 2 trimmed [dry run]",
                      p.stdout)
        self.assertEqual(len(self.rows()), 2)
        p = self.clean()
        self.assertIn("total: 2 removed, 0 would remove, 0 skipped, 0 orphan(s), 0 sandbox dir(s) kept, 0 pooled, 2 trimmed\n", p.stdout + "\n")
        self.assertTrue(p.stdout.rstrip().endswith("0 pooled, 2 trimmed"))
        self.assertEqual(self.rows(), [])

    # T-0018 item 2: a failed `git branch -D` puts the dir back on its task branch and does not pool it
    def test_release_branch_delete_failure_restores_branch(self):
        self.cfg()
        wt, branch, _ = self.task()
        common = Path(git("rev-parse", "--git-common-dir", cwd=self.repo))
        common = common if common.is_absolute() else self.repo / common
        lock = common / "refs" / "heads" / "factory" / "t-0001.lock"
        lock.write_text("")
        self.addCleanup(lambda: lock.unlink(missing_ok=True))
        p = self.clean()
        self.assertIn("branch delete failed:", p.stdout)
        self.assertNotIn("released to pool", p.stdout)
        self.assertEqual(git("symbolic-ref", "HEAD", cwd=wt), "refs/heads/factory/t-0001")
        self.assertEqual(self.env.sql("SELECT worktree FROM tasks WHERE id='T-0001'")[0]["worktree"], str(wt))
        self.assertEqual(self.rows(), [])
        self.assertEqual(self.events("worktree-pooled"), [])
        self.assertTrue(wt.is_dir())
        lock.unlink()
        p = self.clean()
        self.assertIn("released to pool", p.stdout)
        self.assertEqual(self.branches(), "")
        self.assertEqual([r["state"] for r in self.rows()], ["free"])

    # T-0018 item 3a: the trim counts free rows only, even when claimed rows are the newest
    def test_trim_counts_only_free_rows_when_claimed_are_newest(self):
        self.cfg(pool_max="2")
        f = [self.pool_wt(f"pool-f{i}", released=f"2026-01-0{i}T00:00:00+00:00") for i in (1, 2, 3)]
        c = []
        for i in (1, 2):
            self.env.seed_task(f"T-009{i}", status="in_progress", pr_url=None)
            wt = self.pool_wt(f"pool-c{i}", state="claimed", task=f"T-009{i}", released=f"2026-02-0{i}T00:00:00+00:00")
            self.env.sql("UPDATE tasks SET worktree=? WHERE id=?", (str(wt), f"T-009{i}"))
            c.append(wt)
        before = [self.snap(w) for w in c]
        p = self.clean()
        self.assertEqual([r["path"] for r in self.rows() if r["state"] == "free"], [str(f[1]), str(f[2])])
        self.assertFalse(f[0].exists())
        self.assertTrue(f[1].exists() and f[2].exists())
        self.assertEqual([r["task_id"] for r in self.rows() if r["state"] == "claimed"], ["T-0091", "T-0092"])
        self.assertTrue(all(w.exists() for w in c))
        self.assertEqual([self.snap(w) for w in c], before)
        self.assertEqual(p.stdout.count("pool over cap"), 1)
        self.assertNotIn("claimed meanwhile", p.stdout)


# CleanPoolTests reuses CleanTests' fixtures only: hide the inherited test_* methods (the loader skips non-callables)
class WorktreeReuseLifecycleTests(FactoryTestCase):
    """G-002 D: spawn -> merge -> clean (pool) -> spawn (reuse) -> clean (trim), through bin/factory subprocesses only.
    Real temp repo + local bare origin; PR states come from the gh stub; no pool row is ever written by the test."""

    def setUp(self):
        super().setUp()
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
        self.wts.mkdir()
        e.seed_project("zz-test-proj")
        e.sql("UPDATE projects SET repo_path=? WHERE id='zz-test-proj'", (str(self.repo),))
        e.seed_goal(project="zz-test-proj")
        e.seed_agent("zz-test-cleaner", "cleaner", goal="G-001")
        self.cfg(worktree_reuse="1", worktree_pool_max="1")

    def cfg(self, **kv):
        for k, v in kv.items():
            self.env.sql("INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, v))

    def spawn(self, n):
        self.env.seed_task(f"T-000{n}", status="todo", pr_url=None)
        p = self.ok("spawn", "coder", "--goal", "G-001", "--task", f"T-000{n}", "--name", f"zz-test-c{n}")
        self.assertNotIn("QUEUED", p.stdout)
        return Path(self.env.sql("SELECT worktree FROM tasks WHERE id=?", (f"T-000{n}",))[0]["worktree"])

    def tw(self, n):
        return self.env.sql("SELECT worktree FROM tasks WHERE id=?", (f"T-000{n}",))[0]["worktree"]

    def merge(self, n, wt):
        """The task's coder commits, pushes and its PR is merged: what `factory clean` needs to see."""
        tid, branch = f"T-000{n}", f"factory/t-000{n}"
        (wt / f"f{n}").write_text("work\n")
        git("add", f"f{n}", cwd=wt)
        git("commit", "-q", "-m", f"work {n}", cwd=wt)
        git("push", "-q", "origin", branch, cwd=wt)
        url = f"https://github.com/zz-test/repo/pull/{n}"
        self.env.seed_pr(url, sha=git("rev-parse", "HEAD", cwd=wt), state="MERGED")
        self.env.sql("UPDATE tasks SET status='done', pr_url=? WHERE id=?", (url, tid))
        self.env.sql("UPDATE agents SET status='exited' WHERE name=?", (f"zz-test-c{n}",))
        (wt / "node_modules" / "pkg").mkdir(parents=True, exist_ok=True)
        (wt / "node_modules" / "pkg" / "index.js").write_text("module.exports = 1\n")

    def clean(self):
        return self.ok("clean", agent="zz-test-cleaner")

    def pool(self, state=None):
        q = "SELECT * FROM worktree_pool" + (" WHERE state=?" if state else "") + " ORDER BY path"
        return self.env.sql(q, (state,) if state else ())

    def listed(self, wt):
        return str(wt) in git("worktree", "list", cwd=self.repo)

    def new_main_commit(self):
        (self.repo / "later").write_text("new\n")
        git("add", "later", cwd=self.repo)
        git("commit", "-q", "-m", "later", cwd=self.repo)
        git("push", "-q", "origin", "main", cwd=self.repo)

    def test_flag_on_spawn_merge_pool_reuse_trim(self):
        # a. fresh W1
        w1 = self.spawn(1)
        self.assertEqual(w1, self.wts / "G-001-T-0001")
        self.merge(1, w1)
        marker = (w1 / "node_modules" / "pkg" / "index.js").read_bytes()
        # b. clean pools it
        p = self.clean()
        self.assertIn("pooled", p.stdout)
        self.assertTrue(w1.is_dir())
        rows = self.pool()
        self.assertEqual([(r["path"], r["state"]) for r in rows], [(str(w1.resolve()), "free")])
        # c. origin/main moves
        self.new_main_commit()
        # d. T-0002 reuses W1
        w1b = self.spawn(2)
        self.assertEqual(self.tw(2), str(w1.resolve()))
        self.assertEqual(w1b.resolve(), w1.resolve())
        self.assertEqual(git("symbolic-ref", "HEAD", cwd=w1), "refs/heads/factory/t-0002")
        self.assertEqual(git("rev-parse", "HEAD", cwd=w1), git("rev-parse", "origin/main", cwd=self.repo))
        self.assertEqual((w1 / "node_modules" / "pkg" / "index.js").read_bytes(), marker)
        self.assertEqual(git("status", "--porcelain", "--untracked-files=all", cwd=w1), "")
        self.assertEqual([(r["path"], r["state"], r["task_id"]) for r in self.pool()], [(str(w1.resolve()), "claimed", "T-0002")])
        # e. T-0002 done but not yet cleaned: W1 stays claimed, T-0003 gets a fresh W3, T-0004 stays in progress
        self.merge(2, w1)
        w3 = self.spawn(3)
        self.assertNotEqual(self.tw(2), self.tw(3))
        self.assertEqual(w3, self.wts / "G-001-T-0003")
        w4 = self.spawn(4)
        self.assertEqual(w4, self.wts / "G-001-T-0004")
        self.merge(3, w3)
        self.assertEqual(self.env.sql("SELECT count(*) c FROM (SELECT 1 FROM worktree_pool WHERE state='claimed' "
                                      "GROUP BY path HAVING count(*)>1)")[0]["c"], 0)
        t4_row = self.env.sql("SELECT * FROM worktree_pool WHERE path=?", (str(w4.resolve()),))
        self.assertEqual(t4_row, [])  # a fresh worktree has no pool row; it must stay that way
        p = self.clean()
        free = self.pool("free")
        self.assertEqual(len(free), 1)
        kept = [w for w in (w1, w3) if w.exists()]
        gone = [w for w in (w1, w3) if not w.exists()]
        self.assertEqual((len(kept), len(gone)), (1, 1))
        self.assertEqual(free[0]["path"], str(kept[0].resolve()))
        self.assertTrue(self.listed(kept[0]))
        self.assertFalse(self.listed(gone[0]))
        self.assertTrue(w4.is_dir())
        self.assertTrue(self.listed(w4))
        self.assertEqual(git("symbolic-ref", "HEAD", cwd=w4), "refs/heads/factory/t-0004")
        self.assertEqual(self.tw(4), str(w4))
        self.assertEqual(self.pool("claimed"), [])

    def test_flag_off_lifecycle_unchanged(self):
        self.cfg(worktree_reuse="0")
        w1 = self.spawn(1)
        self.merge(1, w1)
        p = self.clean()
        self.assertFalse(w1.exists())
        self.assertIn("removed merged and clean", " ".join(p.stdout.split()))
        self.assertNotIn("pooled", p.stdout)
        self.new_main_commit()
        w2 = self.spawn(2)
        self.assertEqual(w2, self.wts / "G-001-T-0002")
        self.assertNotEqual(w2, w1)
        self.assertTrue(w2.is_dir())
        self.assertFalse(self.listed(w1))
        self.assertEqual(self.env.sql("SELECT count(*) c FROM worktree_pool")[0]["c"], 0)

    def test_flag_off_after_pooling_drains_free_rows_only(self):
        self.cfg(worktree_pool_max="2")
        w1, w2 = self.spawn(1), self.spawn(2)
        self.merge(1, w1)
        self.merge(2, w2)
        self.clean()
        self.assertEqual(len(self.pool("free")), 2)
        w3 = self.spawn(3)  # reuses one of them
        self.assertIn(w3.resolve(), (w1.resolve(), w2.resolve()))
        self.assertEqual((len(self.pool("free")), len(self.pool("claimed"))), (1, 1))
        claimed_path = Path(self.pool("claimed")[0]["path"])
        free_path = Path(self.pool("free")[0]["path"])
        self.cfg(worktree_reuse="0")
        self.clean()
        self.assertFalse(free_path.exists())
        self.assertFalse(self.listed(free_path))
        self.assertEqual(self.pool("free"), [])
        self.assertTrue(claimed_path.is_dir())
        self.assertEqual([(r["path"], r["state"], r["task_id"]) for r in self.pool()], [(str(claimed_path), "claimed", "T-0003")])

    def poison(self, wt):
        """Forbidden core.fsmonitor in wt's admin config.worktree; returns (marker, config.worktree path)."""
        marker = self.env.home / "marker"
        script = self.env.home / "mon.sh"
        script.write_text(f"#!/bin/sh\ntouch {marker}\n")
        script.chmod(0o755)
        cw = Path(git("rev-parse", "--absolute-git-dir", cwd=wt)) / "config.worktree"
        cw.write_text(f"[core]\n\tfsmonitor = {script}\n")
        return marker, cw

    def spawn_rc(self, n):
        self.env.seed_task(f"T-000{n}", status="todo", pr_url=None)
        return self.refused(4, "spawn", "coder", "--goal", "G-001", "--task", f"T-000{n}", "--name", f"zz-test-c{n}")

    def test_poisoned_pooled_worktree_spawn_message(self):
        w1 = self.spawn(1)
        self.merge(1, w1)
        self.clean()
        self.assertEqual([r["state"] for r in self.pool()], ["free"])
        marker, cw = self.poison(w1)
        p = self.spawn_rc(2)
        out = p.stdout + p.stderr
        self.assertIn("spawn refused: git config in", out)
        self.assertIn(f"pooled worktree {w1.resolve()} (free) has ", out)
        self.assertIn("config.worktree: move that file out of the repository", out)
        self.assertIn("Poisoned pooled worktree", out)
        self.assertFalse(marker.exists())
        self.assertEqual([r["state"] for r in self.pool()], ["free"])
        self.assertIsNone(self.tw(2))
        quarantine = self.env.home / "quarantine"
        quarantine.mkdir()
        cw.rename(quarantine / "config.worktree")
        self.ok("spawn", "coder", "--goal", "G-001", "--task", "T-0002", "--name", "zz-test-c2")
        self.assertEqual(self.tw(2), str(w1.resolve()))

    def test_poisoned_unpooled_worktree_message_unchanged(self):
        w1 = self.spawn(1)
        marker, _ = self.poison(w1)
        p = self.spawn_rc(2)
        out = p.stdout + p.stderr
        self.assertIn("spawn refused: git config in", out)
        self.assertNotIn("pooled worktree", out)
        self.assertFalse(marker.exists())


for _n in [n for n in dir(CleanTests) if n.startswith("test_") and n not in CleanPoolTests.__dict__]:
    setattr(CleanPoolTests, _n, None)


if __name__ == "__main__":
    unittest.main()
