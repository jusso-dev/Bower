import unittest

from reuse_pr_result import decide

BEFORE, HEAD, PR_HEAD, RUN = "b" * 40, "m" * 40, "p" * 40, 42
SOURCE = {"repo": {"full_name": "jusso-dev/Bower"}, "ref": "fix/thing", "sha": PR_HEAD}


class Repo:
    """A fake push: HEAD merges PR_HEAD onto BEFORE. Override any fact to break one rule."""

    def __init__(self, parent=BEFORE, pr_tree="T", contains_before=True, pulls=None, runs=None, jobs=None):
        self.parent, self.pr_tree, self.contains_before = parent, pr_tree, contains_before
        self.pulls = pulls if pulls is not None else [
            {"number": 7, "merged_at": "2026-11-17T00:00:00Z", "merge_commit_sha": HEAD, "head": SOURCE}]
        self.runs = runs if runs is not None else [
            {"id": RUN, "head_branch": "fix/thing", "head_repository": {"full_name": "jusso-dev/Bower"}}]
        self.jobs = jobs if jobs is not None else [
            {"name": name, "conclusion": "success"} for name in (
                "changes", "build-test", "linux-arm64", "windows-event-log", "e2e",
                "publish (linux-x64, ubuntu-latest)", "publish (win-x64, windows-latest)")]

    def git(self, *args):
        if args[0] == "fetch":
            return ""
        ref = args[1]
        return {f"{HEAD}^1": self.parent, BEFORE: BEFORE, f"{HEAD}^{{tree}}": "T",
                f"{PR_HEAD}^{{tree}}": self.pr_tree}[ref]

    def is_ancestor(self, ancestor, descendant):
        return (ancestor, descendant) == (BEFORE, PR_HEAD) and self.contains_before

    def api(self, path):
        if path.endswith(f"commits/{HEAD}/pulls"):
            return self.pulls
        if "/actions/workflows/ci.yml/runs?" in path:
            assert f"head_sha={PR_HEAD}" in path and "event=pull_request" in path and "status=success" in path
            return {"workflow_runs": self.runs}
        if path.endswith(f"runs/{RUN}/jobs?per_page=100"):
            return {"jobs": self.jobs}
        raise AssertionError(path)

    def decide(self, selected=("dotnet", "windows", "e2e")):
        return decide("jusso-dev/Bower", BEFORE, HEAD, set(selected),
                      git=self.git, is_ancestor=self.is_ancestor, api=self.api)


class ReuseTests(unittest.TestCase):
    def test_reuses_a_passed_run_of_the_same_tree(self):
        reuse, reason = Repo().decide()
        self.assertTrue(reuse, reason)
        self.assertIn("run 42", reason)

    def test_nothing_selected_needs_only_the_same_tree(self):
        self.assertTrue(Repo(jobs=[]).decide(selected=())[0])

    def test_validates_when_any_rule_fails(self):
        cases = {
            "several commits pushed": Repo(parent="x" * 40),
            "direct push, no pull request": Repo(pulls=[]),
            "pull request not merged": Repo(pulls=[{"number": 7, "merged_at": None, "merge_commit_sha": HEAD, "head": SOURCE}]),
            "another pull request's merge": Repo(pulls=[{"number": 7, "merged_at": "x", "merge_commit_sha": "o" * 40, "head": SOURCE}]),
            "two candidate pull requests": Repo(pulls=[{"number": n, "merged_at": "x", "merge_commit_sha": HEAD, "head": SOURCE} for n in (7, 8)]),
            "merged without the latest main": Repo(contains_before=False),
            "main tree differs from the head": Repo(pr_tree="U"),
            "no successful run": Repo(runs=[]),
            "run from another branch": Repo(runs=[{"id": RUN, "head_branch": "other", "head_repository": {"full_name": "jusso-dev/Bower"}}]),
            "run from a fork of the same name": Repo(runs=[{"id": RUN, "head_branch": "fix/thing", "head_repository": {"full_name": "fork/Bower"}}]),
            "selected job skipped in the run": Repo(jobs=[{"name": "build-test", "conclusion": "success"},
                                                          {"name": "linux-arm64", "conclusion": "skipped"},
                                                          {"name": "windows-event-log", "conclusion": "success"},
                                                          {"name": "e2e", "conclusion": "success"}]),
        }
        for name, repo in cases.items():
            with self.subTest(name):
                self.assertFalse(repo.decide()[0])

    def test_every_matrix_leg_must_pass(self):
        jobs = Repo().jobs + [{"name": "publish (osx-x64, macos-15-intel)", "conclusion": "failure"},
                              {"name": "publish-macos (osx-arm64, macos-latest)", "conclusion": "success"}]
        reuse, reason = Repo(jobs=jobs).decide(selected=("platforms",))
        self.assertFalse(reuse)
        self.assertIn("publish", reason)

    def test_a_push_may_select_more_than_the_pull_request_ran(self):
        # The pull request run selected against an older base; containers never ran.
        self.assertFalse(Repo().decide(selected=("dotnet", "containers"))[0])


if __name__ == "__main__":
    unittest.main()
