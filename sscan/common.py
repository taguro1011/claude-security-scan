"""共通部品: Finding / Coverage / コマンド実行。

このツールは読み取り専用。外部状態を変える API は呼ばない。
秘密値はどの出力にも載せない（gitleaks は --redact、env は名前だけ）。
"""
from __future__ import annotations

import hashlib
import json
import ntpath
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bin"
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_JA = {"critical": "緊急", "high": "高", "medium": "中", "low": "低", "info": "情報"}
IS_WIN = sys.platform == "win32"


def _extra_path() -> list[str]:
    """launchd / タスクスケジューラから呼ばれても CLI が見つかるように補う置き場。"""
    if not IS_WIN:
        return ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    env = os.environ.get
    cands = [
        Path(env("LOCALAPPDATA", "")) / "Microsoft/WinGet/Links",
        Path(env("ProgramFiles", "")) / "GitHub CLI",
        Path(env("ProgramFiles", "")) / "Git/cmd",
        Path(env("ProgramFiles", "")) / "Amazon/AWSCLIV2",
        Path(env("ProgramFiles", "")) / "Microsoft SDKs/Azure/CLI2/wbin",
        Path(env("ProgramFiles(x86)", "")) / "Microsoft SDKs/Azure/CLI2/wbin",
        Path(env("LOCALAPPDATA", "")) / "Google/Cloud SDK/google-cloud-sdk/bin",
        Path(env("APPDATA", "")) / "npm",
        Path.home() / "scoop/shims",
    ]
    return [str(p) for p in cands if str(p) not in (".", "") and p.is_dir()]


os.environ["PATH"] = os.pathsep.join([str(BIN), *_extra_path(), os.environ.get("PATH", "")])
os.environ.setdefault("USER", Path.home().name)
os.environ.setdefault("HOME", str(Path.home()))
if IS_WIN:
    # az / gcloud など Python製CLIの出力を UTF-8 にそろえる（日本語Windowsの既定は cp932）
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    # 子プロセス（cmd.exe 等）にも「今いるフォルダの実行ファイルを探さない」を伝える
    os.environ["NoDefaultCurrentDirectoryInExePath"] = "1"


@dataclass
class Finding:
    module: str
    severity: str
    title: str
    target: str
    detail: str = ""
    fix: str = ""
    # 差分判定に使う安定キー。detail が毎回変わる項目（件数など）でも同一扱いにする
    key: str = ""

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(self.severity)
        if not self.key:
            self.key = hashlib.sha1(f"{self.module}|{self.title}|{self.target}".encode()).hexdigest()[:16]

    def to_dict(self):
        return asdict(self)


WHOLE = [("*", "*")]  # モジュール全体が見えていない


@dataclass
class Coverage:
    module: str
    item: str
    status: str  # ok / skip / error
    message: str = ""
    # この確認が通らなかったときに「解消」「新規」の判定から外す指摘の範囲。
    # (タイトルに含む文字列, 対象に含む文字列) の組。省略時は対象に item を含む指摘。("*","*") はモジュール全体
    blocks: list = None

    def __post_init__(self):
        if self.blocks is None:
            self.blocks = [] if self.status == "ok" else [("", self.item)]

    def to_dict(self):
        return asdict(self)


@dataclass
class Result:
    findings: list[Finding] = field(default_factory=list)
    coverage: list[Coverage] = field(default_factory=list)

    def add(self, *a, **kw):
        self.findings.append(Finding(*a, **kw))

    def cov(self, *a, **kw):
        self.coverage.append(Coverage(*a, **kw))

    def extend(self, other: "Result"):
        self.findings += other.findings
        self.coverage += other.coverage


def tool(name: str) -> str | None:
    """同梱の bin/ を優先し、無ければ PATH から探す。見つからなければ None。"""
    for local in (BIN / name, BIN / f"{name}.exe"):
        if local.is_file():
            return str(local)
    return which(name)


_WIN_EXTS = (".exe", ".cmd", ".bat", ".com")


def which(name: str) -> str | None:
    """Windows では「今いるフォルダ」を探さない which。
    shutil.which は Python 3.11 だとカレントディレクトリを最初に探すので、怪しいリポジトリの中で実行すると
    そこに置かれた git.cmd などを拾ってしまう。PATH の絶対パスと、.exe/.cmd/.bat/.com だけを見る。"""
    if not IS_WIN:
        return shutil.which(name)
    exts = ("",) if name.lower().endswith(_WIN_EXTS) else _WIN_EXTS
    if ntpath.isabs(name):
        return next((name + e for e in exts if os.path.isfile(name + e)), None)
    if ntpath.dirname(name):
        return None  # 相対パスは受け付けない
    for d in os.environ.get("PATH", "").split(os.pathsep):
        d = d.strip().strip('"')
        if not d or not ntpath.isabs(d):
            continue
        for e in exts:
            cand = ntpath.join(d, name + e)
            if os.path.isfile(cand):
                return cand
    return None


def system_exe(name: str) -> str:
    """Windows の System32 にある実行ファイルの絶対パス（32bit版Pythonからでも64bit版を使う）。"""
    root = os.environ.get("SystemRoot", r"C:\Windows")
    native = ntpath.join(root, "Sysnative")  # 32bit プロセスから見た本物の System32
    base = native if os.path.isdir(native) else ntpath.join(root, "System32")
    return ntpath.join(base, name)


def powershell() -> str:
    return system_exe(r"WindowsPowerShell\v1.0\powershell.exe")


# cmd.exe は二重引用符の中でも % と ! を展開する。引数に混ざっていたら .cmd 経由では実行しない
_CMD_UNSAFE = re.compile(r'["%!\r\n\x00]')


def _win_argv(cmd: list[str]) -> list[str] | str:
    """Windows では az / gcloud / vercel 等が .cmd なので、PATH から解決し、.cmd/.bat は安全に引用して cmd.exe に渡す。"""
    exe = which(cmd[0])
    if not exe:
        raise FileNotFoundError(cmd[0])
    if not exe.lower().endswith((".cmd", ".bat")):
        return [exe, *cmd[1:]]
    parts = [exe, *cmd[1:]]
    if any(_CMD_UNSAFE.search(a) for a in parts):
        raise ValueError("cmd.exe で安全に渡せない文字を含む引数")
    # /s: 外側の引用符だけを外す。各引数は "..." で囲むので & | < > ^ ( ) はそのまま文字として渡る
    return f'"{system_exe("cmd.exe")}" /d /s /c "' + " ".join(f'"{a}"' for a in parts) + '"'


def _kill_tree(p: subprocess.Popen):
    """タイムアウト時に子プロセスごと止める（.cmd 経由の node / python が残ってパイプを掴み続けるのを防ぐ）。"""
    if IS_WIN:
        subprocess.run([system_exe("taskkill.exe"), "/T", "/F", "/PID", str(p.pid)], capture_output=True,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    p.kill()


def run(cmd: list[str], timeout: int = 120, cwd: str | None = None) -> tuple[int, str, str]:
    try:
        kw = {}
        if IS_WIN:
            argv = _win_argv(cmd)
            kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)  # 定期実行中に黒い窓を出さない
        else:
            argv = cmd
        with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True,
                              encoding="utf-8", errors="replace", cwd=cwd, **kw) as p:
            try:
                out, err = p.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                _kill_tree(p)
                try:
                    p.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                return 124, "", f"timeout after {timeout}s"
            return p.returncode, out or "", err or ""
    except ValueError as e:
        return 126, "", str(e)
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"


def run_json(cmd: list[str], timeout: int = 120, cwd: str | None = None):
    """JSON を返すコマンドを実行する。失敗時は (None, エラー文) を返す。"""
    rc, out, err = run(cmd, timeout, cwd)
    if rc != 0:
        return None, short_err((err.strip() or out.strip())[-400:])
    try:
        return json.loads(out), ""
    except json.JSONDecodeError:
        start = min([i for i in (out.find("{"), out.find("[")) if i >= 0], default=-1)
        if start >= 0:
            try:
                return json.loads(out[start:]), ""
            except json.JSONDecodeError:
                pass
        return None, "JSON parse error（応答本文は記録しない）"


_TOKENISH = re.compile(r"[A-Za-z0-9_\-+/=]{24,}")
_ASSIGN = re.compile(r"(?i)\b([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|AUTH)[A-Z0-9_]*)\s*[=:]\s*\S+")
_URL_CRED = re.compile(r"(https?://)[^/@\s]+@")


def redact(msg: str) -> str:
    """エラー文に紛れ込んだ秘密値らしきものを伏せる（URLの認証情報・KEY=値・長いトークン列）。"""
    msg = _URL_CRED.sub(r"\1***@", msg)
    msg = _ASSIGN.sub(r"\1=***", msg)
    return _TOKENISH.sub(lambda m: m.group(0)[:4] + "***", msg)


def short_err(msg: str) -> str:
    return redact(" ".join(msg.split()))[:300]
