"""workspace.py: слои 2 и 4 (файлы и процессы).

Слой 2: git-коммит как якорь воркспейса; откат = reset --hard + clean -fdx (кроме env-каталогов).
Слой 4: любой процесс запускается в своей группе; перед откатом группы убиваются и проверяется,
что в них не осталось живых процессов (по /proc, а не по надежде на PID).

Ограничения MVP (честно):
  * .venv и node_modules НЕ снапшотятся и НЕ откатываются; в снапшот пишется только хеш lock-файлов.
    Установку пакетов нужно считать эффектом (effects.py), а не частью воркспейса.
  * Это не песочница: тот же UID, нет изоляции сети и файловой системы.
"""
from __future__ import annotations

import hashlib
import io
import os
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

ENV_DIRS = frozenset({".venv", "node_modules"})
LOCKFILES = (
    "requirements.txt",
    "requirements.lock",
    "poetry.lock",
    "uv.lock",
    "pyproject.toml",
    "package-lock.json",
)
_GITIGNORE_LINES = (".venv/", "node_modules/", "__pycache__/", "*.pyc")
_MAX_OUTPUT = 1_000_000


class WorkspaceError(RuntimeError):
    """Ошибка git-операции или восстановления."""


class WorkspaceSecurityError(PermissionError):
    """Путь выходит за воркспейс или указывает в защищённую зону."""


@dataclass(frozen=True)
class WorkspaceSnapshot:
    commit: str
    tree: str
    manifest: str
    env_hash: str


@dataclass(frozen=True)
class RunResult:
    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool


def _pids_in_group(pgid: int) -> list[int]:
    """Живые (не zombie) процессы с данным pgrp. Читает /proc."""
    found: list[int] = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return found
    for name in entries:
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat", "rb") as fh:
                data = fh.read().decode("utf-8", "replace")
        except OSError:
            continue
        tail = data[data.rfind(")") + 2 :].split()
        if len(tail) < 3:
            continue
        state, pgrp = tail[0], tail[2]
        if state != "Z" and pgrp == str(pgid):
            found.append(int(name))
    return found


def _wait_group_empty(pgid: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if not _pids_in_group(pgid):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.005)


class WorkspaceManager:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._background: list[tuple[int, subprocess.Popen[bytes], str]] = []
        self._ensure_repo()

    # ---- git ----
    def _git(self, *args: str, cwd: Path | None = None) -> str:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.root), "LANG": "C.UTF-8"}
        proc = subprocess.run(
            ["git", "-c", "user.name=sre-arbiter", "-c", "user.email=arbiter@sre.local",
             "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *args],
            cwd=str(cwd or self.root),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode != 0:
            raise WorkspaceError(f"git {' '.join(args)} -> {proc.returncode}: {proc.stderr.decode('utf-8', 'replace').strip()}")
        return proc.stdout.decode("utf-8", "replace").strip()

    def _ensure_repo(self) -> None:
        if not (self.root / ".git").exists():
            self._git("init", "-q")
        gitignore = self.root / ".gitignore"
        have = set(gitignore.read_text(encoding="utf-8").splitlines()) if gitignore.exists() else set()
        missing = [line for line in _GITIGNORE_LINES if line not in have]
        if missing:
            with gitignore.open("a", encoding="utf-8") as fh:
                for line in missing:
                    fh.write(line + "\n")

    # ---- безопасность путей ----
    def resolve_safe_path(self, rel: str | Path) -> Path:
        candidate = (self.root / rel).resolve()
        if not candidate.is_relative_to(self.root):
            raise WorkspaceSecurityError(f"path escapes workspace: {rel!r}")
        parts = candidate.relative_to(self.root).parts
        if parts and (parts[0] == ".git" or parts[0] in ENV_DIRS):
            raise WorkspaceSecurityError(f"protected directory: {parts[0]!r}")
        return candidate

    # ---- хеши состояния ----
    def env_hash(self) -> str:
        h = hashlib.sha256()
        for name in LOCKFILES:
            p = self.root / name
            if p.is_file():
                h.update(name.encode() + b"\0" + hashlib.sha256(p.read_bytes()).digest())
        return h.hexdigest()

    def manifest_hash(self) -> str:
        """Побайтовый слепок рабочего дерева (путь, права, sha256), без .git, env-каталогов и __pycache__."""
        records: list[bytes] = []
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            rel_dir = Path(dirpath).relative_to(self.root)
            dirnames[:] = sorted(
                d for d in dirnames
                if d != "__pycache__" and not (rel_dir == Path(".") and (d == ".git" or d in ENV_DIRS))
            )
            for fname in sorted(filenames):
                if fname.endswith(".pyc"):
                    continue
                fpath = Path(dirpath) / fname
                st = fpath.lstat()
                rel = fpath.relative_to(self.root).as_posix()
                if os.path.islink(fpath):
                    digest = hashlib.sha256(b"link:" + os.readlink(fpath).encode("utf-8", "surrogateescape")).hexdigest()
                elif os.path.isfile(fpath):
                    digest = hashlib.sha256(fpath.read_bytes()).hexdigest()
                else:
                    continue
                records.append(f"{rel}\0{st.st_mode & 0o777:04o}\0{digest}\n".encode("utf-8", "surrogateescape"))
        h = hashlib.sha256()
        for rec in records:
            h.update(rec)
        return h.hexdigest()

    def _describe(self) -> WorkspaceSnapshot:
        return WorkspaceSnapshot(
            commit=self._git("rev-parse", "HEAD"),
            tree=self._git("rev-parse", "HEAD^{tree}"),
            manifest=self.manifest_hash(),
            env_hash=self.env_hash(),
        )

    # ---- слой 2 ----
    def snapshot(self, message: str = "sre-anchor") -> WorkspaceSnapshot:
        self.kill_background()
        self._git("add", "-A")
        self._git("commit", "-q", "--allow-empty", "--no-verify", "-m", message)
        return self._describe()

    def restore(self, commit: str) -> WorkspaceSnapshot:
        if len(commit) < 7 or not all(c in "0123456789abcdef" for c in commit):
            raise WorkspaceError(f"bad commit id: {commit!r}")
        self.kill_background()
        self._git("reset", "-q", "--hard", commit)
        self._git("clean", "-q", "-fdx", "-e", ".venv", "-e", "node_modules")
        snap = self._describe()
        if snap.commit != commit:
            raise WorkspaceError(f"restore mismatch: wanted {commit}, got {snap.commit}")
        return snap

    def tracked_files(self, commit: str) -> frozenset[str]:
        """Имена файлов, существовавшие в коммите (доверенные: их можно показывать агенту)."""
        out = self._git("ls-tree", "-r", "--name-only", commit)
        return frozenset(line for line in out.splitlines() if line)

    def read_at(self, commit: str, rel_path: str) -> str | None:
        """Содержимое файла в коммите (None, если файла там не было)."""
        try:
            return self._git("show", f"{commit}:{rel_path}")
        except WorkspaceError:
            return None

    def export_commit(self, commit: str, dest: str | Path) -> Path:
        """Чистая копия коммита в dest (для контрольного прогона на якоре). Без .venv."""
        proc = subprocess.run(
            ["git", "archive", "--format=tar", commit],
            cwd=str(self.root), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if proc.returncode != 0:
            raise WorkspaceError(f"git archive failed: {proc.stderr.decode('utf-8', 'replace').strip()}")
        dest_path = Path(dest)
        dest_path.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(proc.stdout)) as tar:
            try:
                tar.extractall(dest_path, filter="data")
            except TypeError:  # Python < 3.10.12
                tar.extractall(dest_path)
        return dest_path

    # ---- слой 4 ----
    @staticmethod
    def _env(scratch: str, extra: dict[str, str] | None) -> dict[str, str]:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": scratch,
            "TMPDIR": scratch,
            "TEMP": scratch,
            "TMP": scratch,
            "XDG_CACHE_HOME": os.path.join(scratch, ".cache"),
            "LANG": "C.UTF-8",
            "PYTHONUTF8": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        if extra:
            env.update(extra)
        return env

    def run_isolated(
        self,
        cmd: list[str],
        timeout: float,
        *,
        cwd: str | Path | None = None,
        env_extra: dict[str, str] | None = None,
    ) -> RunResult:
        """Запуск с ожиданием. Группа убивается пока лидер ещё zombie (PID не может быть переиспользован)."""
        scratch = tempfile.mkdtemp(prefix="sre_run_")
        out_path, err_path = os.path.join(scratch, "stdout"), os.path.join(scratch, "stderr")
        try:
            with open(out_path, "wb") as out_f, open(err_path, "wb") as err_f:
                proc = subprocess.Popen(
                    cmd, cwd=str(cwd or self.root), env=self._env(scratch, env_extra),
                    stdin=subprocess.DEVNULL, stdout=out_f, stderr=err_f, start_new_session=True,
                )
                pgid = proc.pid
                timed_out = False
                deadline = time.monotonic() + timeout
                while True:
                    try:
                        done = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    except ChildProcessError:
                        break
                    if done is not None:
                        break
                    if time.monotonic() >= deadline:
                        timed_out = True
                        break
                    time.sleep(0.003)
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
                _wait_group_empty(pgid, 2.0)
            with open(out_path, "rb") as fh:
                stdout = fh.read(_MAX_OUTPUT)
            with open(err_path, "rb") as fh:
                stderr = fh.read(_MAX_OUTPUT)
            return RunResult(None if timed_out else proc.returncode, stdout, stderr, timed_out)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def spawn_background(
        self, cmd: list[str], *, env_extra: dict[str, str] | None = None
    ) -> subprocess.Popen[bytes]:
        """Долгоживущий процесс ветки (сервер, watcher). Будет убит при snapshot()/restore()."""
        scratch = tempfile.mkdtemp(prefix="sre_bg_")
        proc = subprocess.Popen(
            cmd, cwd=str(self.root), env=self._env(scratch, env_extra),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self._background.append((proc.pid, proc, scratch))
        return proc

    def kill_background(self, timeout: float = 3.0) -> None:
        """Убить все фоновые группы и убедиться по /proc, что они пусты."""
        survivors: list[int] = []
        for pgid, proc, scratch in self._background:
            if _pids_in_group(pgid):
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                pass
            if not _wait_group_empty(pgid, timeout):
                survivors.append(pgid)
            shutil.rmtree(scratch, ignore_errors=True)
        self._background.clear()
        if survivors:
            raise WorkspaceError(f"process groups survived SIGKILL: {survivors}")
