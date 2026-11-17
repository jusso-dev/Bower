"""Skip a push to main that repeats checks a pull request run already passed.

The changes job runs this on pushes to main after selecting checks. It keeps the
selection only when it cannot prove the work was done. A push is reused only if all
of these hold; anything else, including any Git or API error, keeps the selection:

- the push adds exactly one commit (BEFORE is HEAD's first parent);
- GitHub reports exactly one merged pull request whose merge commit is HEAD;
- the pull request head contains BEFORE and has HEAD's tree. A pull_request run tests
  the head merged into the base of its time; main only moves forward, so that base is
  an ancestor of BEFORE and of the head, the merge is the head's tree, and the commit
  on main is byte-for-byte what the run built and tested;
- a successful CI pull_request run of that head, from the pull request's own branch,
  ran and passed every job of every group selected for this push. The pull request run selected against an older base,
  so it may have selected less than the push does; then the push runs.

Merge commits and squash merges of up-to-date pull requests qualify. A pull request
merged without the latest main does not, and main runs its selected checks.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from select_jobs import GROUPS, JOBS, changed_paths, select


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout.strip()


def is_ancestor(ancestor, descendant):
    return subprocess.run(["git", "merge-base", "--is-ancestor", ancestor, descendant]).returncode == 0


def gh_api(path):
    return json.loads(subprocess.run(["gh", "api", path], check=True, capture_output=True, text=True).stdout)


def decide(repo, before, head, selected, git=git, is_ancestor=is_ancestor, api=gh_api):
    """Return (reuse, reason) for a push of HEAD whose selected groups are `selected`."""
    if git("rev-parse", f"{head}^1") != git("rev-parse", before):
        return False, "the push adds more than one commit"
    pulls = [pr for pr in api(f"repos/{repo}/commits/{head}/pulls")
             if pr.get("merged_at") and pr.get("merge_commit_sha") == head]
    if len(pulls) != 1:
        return False, "no single merged pull request has this merge commit"
    number, pr_head = pulls[0]["number"], pulls[0]["head"]["sha"]
    git("fetch", "--quiet", "--no-tags", "origin", f"refs/pull/{number}/head")
    if not is_ancestor(before, pr_head):
        return False, f"#{number} was merged without the latest main"
    if git("rev-parse", f"{head}^{{tree}}") != git("rev-parse", f"{pr_head}^{{tree}}"):
        return False, f"#{number} head tree differs from main"
    # The same commit can head pull requests into other branches; take only this one's runs.
    source = (pulls[0]["head"]["repo"] or {}).get("full_name"), pulls[0]["head"]["ref"]
    runs = [run for run in api(f"repos/{repo}/actions/workflows/ci.yml/runs"
                               f"?head_sha={pr_head}&event=pull_request&status=success")["workflow_runs"]
            if ((run.get("head_repository") or {}).get("full_name"), run.get("head_branch")) == source]
    if not runs:
        return False, f"no successful CI pull_request run of #{number} head {pr_head[:12]}"
    run = runs[0]["id"]
    jobs = api(f"repos/{repo}/actions/runs/{run}/jobs?per_page=100")["jobs"]
    passed = {}
    for job in jobs:
        name = job["name"].split(" (", 1)[0]
        passed[name] = passed.get(name, True) and job["conclusion"] == "success"
    missing = sorted(job for group in selected for job in GROUPS[group] if not passed.get(job))
    if missing:
        return False, f"run {run} of #{number} did not pass {', '.join(missing)}"
    return True, f"run {run} passed every selected check on #{number} head {pr_head[:12]}, the same tree"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--before", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()
    if set(args.before) == {"0"}:
        # A new branch has no range to compare: validate everything, as select_jobs.py does.
        selected = set(JOBS)
    else:
        # Git errors here fail the job, as in select_jobs.py: never guess a selection.
        selected = {job for job, enabled in select(changed_paths(args.before, args.head)).items() if enabled}
    try:
        reuse, reason = decide(args.repo, args.before, args.head, selected)
    except (subprocess.CalledProcessError, OSError, ValueError, KeyError, TypeError) as error:
        reuse, reason = False, f"could not check ({type(error).__name__})"
    print(f"{'Reusing' if reuse else 'Validating'}: {reason}", file=sys.stderr)
    result = {job: job in selected and not reuse for job in JOBS}
    output = "".join(f"{job}={str(enabled).lower()}\n" for job, enabled in result.items())
    print(output, end="")
    if target := os.environ.get("GITHUB_OUTPUT"):
        with Path(target).open("a", encoding="utf-8") as stream:
            stream.write(output)


if __name__ == "__main__":
    main()
