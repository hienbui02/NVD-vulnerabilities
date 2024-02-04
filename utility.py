import re
from pydriller import Repository


def is_git_commit_link(link):
    # Check if the link starts with a known git hosting provider URL.
    if not re.match(r"^(https?://)?(www\.)?github\.com/(.*?)/(.*?)/commit/", link):
        return False
    # Check if the link contains a valid commit hash.
    commit_hash = re.search(r"/commit/(.{40})", link).group(1)
    if not re.match(r"^[0-9a-f]{40}$", commit_hash):
        return False
    return True


def get_code_diff(commit_link):
    commit_hash = commit_link.split("/")[-1]
    repo_link = commit_link.split("/commit/")[0]
    diffs = []
    try:
        repo = Repository(repo_link)

        for commit in repo.traverse_commits():
            if commit.hash == commit_hash:
                try:
                    for f in commit.modified_files:
                        diffs.append({'filename': f.filename,'content':f.content_before ,'diff': f.diff_parsed})
                except Exception:
                    continue
    except Exception:
        pass
    return diffs 
