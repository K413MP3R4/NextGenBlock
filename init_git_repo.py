import hashlib
import os
import stat
import time
from pathlib import Path

root = Path(r"d:\Claude Code\NextGenBlock")
git_dir = root / ".git"
if git_dir.exists():
    print("Git repository already exists.")
    raise SystemExit(1)

def write_file(path, data, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)

write_file(git_dir / "HEAD", b"ref: refs/heads/main\n")
write_file(git_dir / "config", b"[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n\tlogallrefupdates = true\n")
write_file(git_dir / "description", b"Unnamed repository; edit this file to name it for gitweb.\n")
write_file(git_dir / "info" / "exclude", b"# git ls-files --others --exclude-from=.git/info/exclude\n")

(git_dir / "objects" / "info").mkdir(parents=True, exist_ok=True)
(git_dir / "objects" / "pack").mkdir(parents=True, exist_ok=True)
(git_dir / "refs" / "heads").mkdir(parents=True, exist_ok=True)
(git_dir / "refs" / "tags").mkdir(parents=True, exist_ok=True)


def hash_object(data: bytes, obj_type: str) -> str:
    header = f"{obj_type} {len(data)}\0".encode("utf-8")
    full = header + data
    digest = hashlib.sha1(full).hexdigest()
    obj_path = git_dir / "objects" / digest[:2] / digest[2:]
    if not obj_path.exists():
        obj_path.parent.mkdir(parents=True, exist_ok=True)
        obj_path.write_bytes(full)
    return digest


def tree_entries(directory: Path):
    entries = []
    for child in sorted(directory.iterdir(), key=lambda p: p.name):
        if child.name == ".git":
            continue
        if child.is_dir():
            tree_hash = write_tree(child)
            entries.append((b"40000", child.name.encode("utf-8"), bytes.fromhex(tree_hash)))
        elif child.is_file():
            data = child.read_bytes()
            mode = b"100755" if os.access(child, os.X_OK) else b"100644"
            blob_hash = hash_object(data, "blob")
            entries.append((mode, child.name.encode("utf-8"), bytes.fromhex(blob_hash)))
    return entries


def write_tree(directory: Path) -> str:
    entries = tree_entries(directory)
    tree_data = b"".join(mode + b" " + name + b"\0" + sha for mode, name, sha in entries)
    return hash_object(tree_data, "tree")

root_tree_hash = write_tree(root)

author_name = "GitHub Copilot"
author_email = "copilot@example.com"
now = int(time.time())
local_offset = time.altzone if time.daylight and time.localtime().tm_isdst else time.timezone
sign = b"-" if local_offset > 0 else b"+"
offset = abs(local_offset)
offset_str = f"{offset // 3600:02d}{(offset % 3600) // 60:02d}".encode("utf-8")
when = f"{now} {sign.decode()}{offset_str.decode()}"
commit_message = "Initial commit\n"
commit_content = (
    f"tree {root_tree_hash}\n"
    f"author {author_name} <{author_email}> {when}\n"
    f"committer {author_name} <{author_email}> {when}\n\n"
    f"{commit_message}"
).encode("utf-8")
commit_hash = hash_object(commit_content, "commit")
write_file(git_dir / "refs" / "heads" / "main", commit_hash.encode("utf-8"))
print(f"Initialized Git repository at {git_dir}")
print(f"Created initial commit {commit_hash}")
