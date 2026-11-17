#!/usr/bin/env python3
"""
skill-security-vetting 자동 감시 훅.

  guard.py pretool        PreToolUse 훅(stdin JSON). 스킬·플러그인·설정 폴더 쓰기 감시 + 위험 명령 확인 요청
  guard.py session        SessionStart 훅. 스킬·플러그인·훅·MCP 설정이 기준선과 달라졌는지 검사
  guard.py baseline-init  현재 상태를 기준선으로 저장(처음 1회, 사용자 승인 후)
  guard.py accept <키|all> 변경을 확인·승인한 뒤 기준선 갱신 (Claude가 실행하면 항상 승인창이 뜸)
  guard.py status         기준선과 현재 차이만 출력
  guard.py vet-start <폴더>          점검 모드 켜기(이 세션만, 훅이 켬. 임시 폴더의 vet-… 폴더)
  guard.py vet-end <폴더> [--discard] 점검 모드 끄기 (--discard: 받은 코드 삭제, 승인 없음 / 아니면 승인창)

표준 라이브러리만 사용, 네트워크 없음, 대상 파일은 읽기만 함.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time

HOME = os.path.expanduser("~")
CL = os.path.join(HOME, ".claude")
SK = os.path.join(CL, "skills", "skill-security-vetting")
STATE = os.path.join(SK, "state")
BASELINE = os.path.join(STATE, "baseline.json")
PENDING = os.path.join(STATE, "pending")
SCAN = os.path.join(SK, "scripts", "scan.py")
LOG = os.path.join(STATE, "guard-log.txt")
IGNORE_NAMES = {".git", "__pycache__", ".DS_Store"}
IGNORE_FILES = {os.path.join(os.path.expanduser("~"), ".claude", "skills", "skill-security-vetting", "installed-log.md")}

# ------------------------------------------------------------------ 공통


def log(msg):
    try:
        os.makedirs(STATE, exist_ok=True)
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\n")
    except Exception:
        pass


def out(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False))
    sys.exit(0)


# ------------------------------------------------------------------ PreToolUse

PROT_PATH = re.compile(
    r"(~|\$HOME|\$\{HOME\}|" + re.escape(HOME) + r")/\.claude/(skills|plugins|agents|commands|hooks|settings[\w.\-]*\.json)"
    r"|(~|\$HOME|" + re.escape(HOME) + r")/\.claude\.json"
    r"|(^|[\s'\"=/])\.claude/(skills|commands|agents|hooks|settings[\w.\-]*\.json)"
    r"|(^|[\s'\"=/])\.mcp\.json"
)
WRITE_VERB = re.compile(
    r"(^|[\s;&|(`])(cp|mv|rsync|ln|ditto|install|unzip|tar|rm|rmdir|mkdir|touch|tee|chmod|chown|truncate|patch|"
    r"sed\s+-[a-zA-Z]*i|perl\s+-[a-zA-Z]*i|git\s+(clone|pull|checkout|reset|apply|am|restore|switch|merge|stash)|"
    r"curl|wget|gh\s+repo\s+clone|npx|bunx|pip3?\s+install|npm\s+(i|install)|find\s.*-delete)\b"
    r"|>>?\s*\S|\bopen\([^)]*['\"][wa]"
)
FETCH_VERB = re.compile(r"\b(git(\s+-[cC]\s+\S+|\s+--[\w-]+(=\S+)?)*\s+clone|gh\s+repo\s+clone|curl|wget|unzip|tar\s+-?[a-zA-Z]*x|svn\s+(checkout|export)|degit)\b")
INSTALL_CMD = re.compile(
    r"\bclaude\s+(plugins?\s+(install|add|update|marketplace)|mcp\s+add)|\bnpx\s+(-y\s+)?[^\s]*skills?\b|"
    r"\b(npx|bunx|uvx|pipx)\s+(-y\s+|run\s+)?[^\s]*mcp[^\s]*"
)

RUNTIME = [
    (r"(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?((ba|z|da)?sh|python3?|node|perl|ruby)\b|(ba|z)?sh\s+<\(\s*(curl|wget)", "다운로드한 코드를 바로 실행"),
    (r"(~|\$HOME|" + re.escape(HOME) + r")/\.ssh\b|\bid_(rsa|ed25519|ecdsa)\b", "SSH 키 폴더 접근"),
    (r"\bsecurity\s+(dump-keychain|find-(generic|internet)-password)|Library/Keychains", "키체인(비밀번호 저장소) 접근"),
    (r"Application Support/(Google/Chrome|BraveSoftware|Arc|Firefox|Microsoft Edge)[^\n]*(Cookies|Login Data|Local State|Web Data)", "브라우저 쿠키·비밀번호 접근"),
    (r"\.aws/credentials|\.config/gcloud|\.git-credentials|\.netrc\b|\bgh\s+auth\s+token\b|\.config/gh/hosts", "클라우드·GitHub 자격증명 접근"),
    (r"LaunchAgents|LaunchDaemons|launchctl\s+(load|bootstrap|enable|submit)", "자동 실행 등록"),
    (r"\bcrontab\s+(?!-l\b)", "예약 작업 변경"),
    (r"(>>?|tee\s+(-a\s+)?)\s*(~|\$HOME|" + re.escape(HOME) + r")/\.(zshrc|bashrc|bash_profile|zprofile|profile|zshenv)", "셸 시작 파일 수정"),
    (r"discord(app)?\.com/api/webhooks|webhook\.site|requestbin|pipedream\.net|interact\.sh|pastebin\.com|transfer\.sh|0x0\.st|file\.io|temp\.sh", "외부 수집·업로드 주소로 전송"),
    (r"/dev/tcp/|\bnc\s+[^\n]*\s-e\s|\bsocat\b[^\n]*exec", "리버스 셸"),
    (r"dangerously-skip-permissions|bypassPermissions", "권한 확인 우회"),
    (r"xattr\s+-[a-z]*d\s+com\.apple\.quarantine|spctl\s+--master-disable", "macOS 보안 검사 해제"),
    (r"osascript[^\n]*(keystroke|System Events)|\bscreencapture\b|tccutil|TCC\.db", "화면·키 입력·개인정보 보호 설정 접근"),
    (r"skill-security-vetting/hooks/guard\.py\s+(accept|baseline-init)", "감시 기준선 변경(승인 필요)"),
]
RUNTIME = [(re.compile(p), d) for p, d in RUNTIME]

# `curl … | python3 [-I] -c "json 읽기"`처럼 받은 데이터를 '보이는 코드'로 읽기만 하는 경우는 실행이 아님.
# 단, 인라인 코드에 exec·eval 등 받은 내용을 실행하는 함수가 있으면 그대로 위험으로 본다.
PIPE_READ_ONLY = re.compile(r"\|\s*python3?\s+(-I\s+)?-c\s+(['\"])(?P<code>.*?)(?<!\\)\2", re.S)
PIPE_EXEC_IN_CODE = re.compile(r"\b(exec|eval|compile|__import__|subprocess|os\.system|os\.popen|runpy|importlib)\b")


def downloaded_code_runs(cmd):
    """curl|wget 결과가 셸·인터프리터로 실행되면 True. python -c 로 JSON만 읽는 경우는 False."""
    rx = RUNTIME[0][0]
    if not rx.search(cmd):
        return False
    rest = cmd
    for m in PIPE_READ_ONLY.finditer(cmd):
        if PIPE_EXEC_IN_CODE.search(m.group("code")):
            return True
        rest = rest.replace(m.group(0), "| <읽기전용>")
    if rx.search(rest):
        return True
    # 읽기 단계 뒤에 다시 셸·인터프리터로 넘기는 경우(curl … | python3 -c … | sh)도 실행으로 본다
    return bool(re.search(r"(curl|wget)\b", rest) and
                re.search(r"\|\s*(sudo\s+)?((ba|z|da)?sh|python3?|node|perl|ruby)\b", rest))

# 승인창 없이 자동 차단하는 '확실한 악성' (RUNTIME 설명 문구 기준)
DENY_DESCS = {
    "다운로드한 코드를 바로 실행",
    "SSH 키 폴더 접근",
    "키체인(비밀번호 저장소) 접근",
    "브라우저 쿠키·비밀번호 접근",
    "클라우드·GitHub 자격증명 접근",
    "외부 수집·업로드 주소로 전송",
    "리버스 셸",
    "권한 확인 우회",
}
BASELINE_CHANGE = re.compile(r"skill-security-vetting/hooks/guard\.py\s+(accept|baseline-init)")

EXEMPT_WRITE = {
    os.path.join(SK, "installed-log.md"),
}


# ------------------------------------------------------------------ 점검 모드 (스킬로 외부 코드를 점검하는 동안만)
# 받은 코드가 컴퓨터에 있는 동안에는 '허용 목록' 방식: 정해진 읽기·점검 명령만 통과, 나머지는 오토 모드와 상관없이 차단.
# 세션별로 켜짐(다른 Claude 세션·평소 작업에는 영향 없음). 2시간 지나면 저절로 꺼짐.

VET_STATE = os.path.join(STATE, "vet-mode")
VET_TTL = 2 * 3600
VET_PATH = re.compile(r"(/[^\s'\"]*?/vet-[A-Za-z0-9._-]+)(?=/|[\s'\"]|$)")


def _tmp_roots():
    roots = set()
    for p in (os.environ.get("TMPDIR"), "/tmp", "/private/tmp", "/var/folders", "/private/var/folders"):
        if p:
            roots.add(os.path.realpath(p))
    return roots


def inside(p, root):
    return p == root or p.startswith(root.rstrip(os.sep) + os.sep)


def _sid_file(sid):
    return os.path.join(VET_STATE, re.sub(r"[^A-Za-z0-9_-]", "_", sid or "nosession")[:80] + ".json")


def vet_load(sid):
    f = _sid_file(sid)
    try:
        with open(f, encoding="utf-8") as fh:
            st = json.load(fh)
    except Exception:
        return None
    if time.time() > st.get("expires", 0):
        try:
            os.remove(f)
        except Exception:
            pass
        log(f"vet-mode 만료로 꺼짐: {st.get('dir')}")
        return None
    return st


def vet_valid_dir(d):
    """점검 폴더로 쓸 수 있는지: 임시 폴더 아래의 vet-… 폴더만."""
    rd = os.path.realpath(os.path.expanduser(d))
    if not os.path.basename(rd).startswith("vet-"):
        return None
    if not any(inside(rd, r) and rd != r for r in _tmp_roots()):
        return None
    return rd


def vet_start(sid, d):
    os.makedirs(VET_STATE, exist_ok=True)
    st = {"dir": d, "session": sid, "started": time.time(), "expires": time.time() + VET_TTL}
    with open(_sid_file(sid), "w", encoding="utf-8") as fh:
        json.dump(st, fh, ensure_ascii=False)
    log(f"vet-mode 켜짐: {d.replace(HOME, '~')}")
    return st


def vet_states():
    out_ = []
    try:
        for fn in os.listdir(VET_STATE):
            if fn.endswith(".json"):
                p = os.path.join(VET_STATE, fn)
                try:
                    with open(p, encoding="utf-8") as fh:
                        out_.append((p, json.load(fh)))
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    return out_


_OPS = ["&&", "||", ";;", ">>", ">&", "|&", "<<", "<", ">", "|", "&", ";", "(", ")", "\n"]


def tokenize(s):
    """셸 명령을 단어·연산자로 나눈다(따옴표 안 글자는 단어). 해석이 애매하면 ValueError."""
    toks, cur, i, n = [], None, 0, len(s)

    def flush():
        nonlocal cur
        if cur is not None:
            toks.append(("w", cur))
            cur = None
    while i < n:
        c = s[i]
        if c in " \t\r":
            flush()
            i += 1
        elif c == "\\":
            if i + 1 < n and s[i + 1] == "\n":
                i += 2
                continue
            if i + 1 >= n:
                raise ValueError("끝의 \\")
            cur = (cur or "") + s[i + 1]
            i += 2
        elif c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                raise ValueError("따옴표 짝 없음")
            cur = (cur or "") + s[i + 1:j]
            i = j + 1
        elif c == '"':
            j, buf = i + 1, ""
            while j < n and s[j] != '"':
                if s[j] == "\\" and j + 1 < n and s[j + 1] in '"\\$`':
                    buf += s[j + 1]
                    j += 2
                else:
                    buf += s[j]
                    j += 1
            if j >= n:
                raise ValueError("따옴표 짝 없음")
            cur = (cur or "") + buf
            i = j + 1
        elif c == "#" and cur is None:
            while i < n and s[i] != "\n":
                i += 1
        else:
            op = next((o for o in _OPS if s.startswith(o, i)), None)
            if op:
                flush()
                toks.append(("op", op))
                i += len(op)
            else:
                cur = (cur or "") + c
                i += 1
    flush()
    return toks


VET_ENV_OK = {"GIT_TERMINAL_PROMPT", "LC_ALL", "LANG", "NO_COLOR"}
VET_HOSTS = {"api.github.com", "github.com", "codeload.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
             "api.securityscorecards.dev", "api.osv.dev", "osv.dev", "registry.npmjs.org", "pypi.org"}
VET_GIT_C_OK = {"core.hooksPath=/dev/null", "protocol.file.allow=never", "core.symlinks=false", "advice.detachedHead=false", "color.ui=never"}
VET_GIT_SUB = {"clone", "rev-parse", "log", "show", "diff", "branch", "ls-files", "ls-tree", "cat-file", "rev-list", "shortlog", "blame"}
PY_IMPORT_OK = {"sys", "json", "re", "collections", "itertools", "textwrap", "unicodedata", "hashlib", "string"}
PY_CODE_BAD = re.compile(r"\b(exec|eval|compile|__import__|subprocess|os|runpy|importlib|open|shutil|socket|urllib|http|ctypes|pty|"
                         r"pathlib|builtins|getattr|setattr|globals|locals|vars|marshal|pickle|codecs|base64|input|breakpoint|help)\b|__")
# 파일을 인자로 받는 읽기 명령: {명령: 값을 받는 옵션(그 값은 경로로 보지 않음)}
VET_READ = {
    "cat": set(), "ls": set(), "wc": set(), "file": set(), "nl": {"-b", "-w", "-s"}, "column": {"-s", "-c"},
    "head": {"-n", "-c"}, "tail": {"-n", "-c"}, "stat": {"-f", "-t"}, "shasum": {"-a"}, "sha256sum": set(), "md5": set(),
    "xxd": {"-l", "-s", "-c", "-g"}, "od": {"-N", "-j", "-t", "-A"}, "hexdump": {"-n", "-s"}, "strings": {"-n"},
    "diff": {"-U"}, "cmp": set(), "du": {"-d"}, "sort": {"-k", "-t"}, "realpath": set(), "tree": {"-L"},
}
VET_PLAIN = {"echo", "printf", "true", "pwd", "basename", "dirname", "date"}
FIRST_IS_PATTERN = {"grep": {"-m", "-A", "-B", "-C", "--include", "--exclude", "--exclude-dir"},
                    "egrep": {"-m", "-A", "-B", "-C"},
                    "rg": {"-m", "-A", "-B", "-C", "-g", "--glob", "-t", "--type", "-T", "--max-count"},
                    "jq": set()}


def vet_check(cmd, cwd, vdir):
    """점검 모드에서 이 명령을 허용하면 None, 아니면 ('deny'|'ask', 이유)."""
    roots_r = [vdir, os.path.realpath(SK)]
    roots_w = [vdir]
    nosq = re.sub(r"'[^']*'", "''", cmd)
    if re.search(r"\$|`", nosq):
        return ("deny", "변수·명령 치환($, `)은 쓸 수 없습니다. 경로를 그대로 적어 주세요.")
    if "<<" in nosq:
        return ("deny", "입력 본문(<<)은 쓸 수 없습니다.")
    norm = re.sub(r"(?<![\w/.\-])\d+(?=>)", "", cmd)  # 2>/dev/null → >/dev/null (해석용)
    try:
        toks = tokenize(norm)
    except ValueError as e:
        return ("deny", f"명령을 해석할 수 없습니다({e}).")

    here = {"cwd": cwd}  # 같은 명령 안의 cd 반영

    def res(p):
        p = os.path.expanduser(p)
        return os.path.realpath(p if os.path.isabs(p) else os.path.join(here["cwd"], p))

    def pathlike(t):
        return "/" in t or t.startswith("~") or t.startswith(".") or os.path.lexists(res(t))

    def ok_path(t, roots):
        if t in ("-", "/dev/null", "/dev/stdin"):
            return True
        r = res(t)
        return any(inside(r, x) for x in roots)

    def need(t, roots, what="점검 폴더"):
        if not ok_path(t, roots):
            raise PermissionError(f"{what} 밖 경로: {t}")

    segs, cur = [], []
    for k, v in toks:
        if k == "op" and v in ("&&", "||", ";", "|", "\n", "&"):
            segs.append(cur)
            cur = []
        elif k == "op" and v in ("(", ")", "|&", ";;", "<<"):
            return ("deny", f"쓸 수 없는 문법: {v!r}")
        else:
            cur.append((k, v))
    segs.append(cur)

    try:
        for seg in segs:
            words, i = [], 0
            while i < len(seg):
                k, v = seg[i]
                if k == "op":
                    if i + 1 >= len(seg) or seg[i + 1][0] != "w":
                        raise PermissionError(f"방향 기호 {v} 뒤 대상 없음")
                    tgt = seg[i + 1][1]
                    if v in (">", ">>"):
                        need(tgt, roots_w, "점검 폴더(쓰기)")
                    elif v == ">&":
                        if not (tgt.isdigit() or tgt == "-"):
                            raise PermissionError(">& 뒤에는 숫자만")
                    elif v == "<":
                        need(tgt, roots_r)
                    i += 2
                    continue
                words.append(v)
                i += 1
            while words and re.match(r"^[A-Za-z_]\w*=", words[0]):
                name = words[0].split("=", 1)[0]
                if name not in VET_ENV_OK:
                    raise PermissionError(f"환경변수 설정 불가: {name}")
                words = words[1:]
            if not words:
                continue
            prog, args = words[0], words[1:]
            if "/" in prog:
                raise PermissionError(f"경로로 프로그램 실행 불가: {prog}")
            r = _vet_prog(prog, args, here["cwd"], vdir, roots_r, roots_w, res, pathlike, need)
            if r:
                return r
            if prog == "cd" and args:
                here["cwd"] = res(args[-1])
    except PermissionError as e:
        return ("deny", str(e))
    return None


def _vet_prog(prog, args, cwd, vdir, roots_r, roots_w, res, pathlike, need):
    opts_flags = [a for a in args if a.startswith("-")]

    def files(args, valopts, skip_first=False):
        skip, first_done = False, not skip_first
        for a in args:
            if skip:
                skip = False
                continue
            if a.startswith("-") and a != "-":
                if "=" in a:
                    v = a.split("=", 1)[1]
                    if pathlike(v):
                        need(v, roots_r)
                elif a in valopts or (prog in FIRST_IS_PATTERN and a in ("-e", "--regexp")):
                    skip = True
                    if a in ("-e", "--regexp"):
                        first_done = True
                continue
            if not first_done:
                first_done = True
                continue
            if pathlike(a):
                need(a, roots_r)

    if prog in VET_PLAIN:
        return None
    if prog == "cd":
        for a in args:
            need(a, roots_r)
        return None
    if prog in VET_READ:
        files(args, VET_READ[prog])
        return None
    if prog in FIRST_IS_PATTERN:
        if prog == "rg" and any(a.startswith(("--pre", "-z", "--search-zip")) for a in args):
            raise PermissionError("rg --pre/-z(외부 프로그램 실행) 불가")
        if prog == "jq" and any(a in ("--rawfile", "--slurpfile", "-L") or a.startswith("--rawfile") for a in args):
            raise PermissionError("jq --rawfile/--slurpfile 불가")
        if any(a in ("-f", "--file") or a.startswith("--file=") for a in args):
            raise PermissionError("패턴 파일(-f) 불가")
        files(args, FIRST_IS_PATTERN[prog], skip_first=True)
        return None
    if prog == "sed":
        if any(a.startswith("-") and "i" in a.lstrip("-") for a in opts_flags) or "-n" not in args:
            raise PermissionError("sed는 `sed -n '시작,끝p' 파일` 형태만")
        pos = [a for a in args if not a.startswith("-")]
        if not pos or not re.fullmatch(r"\d+(,(\d+|\$))?p", pos[0]):
            raise PermissionError("sed는 `sed -n '시작,끝p' 파일` 형태만")
        for a in pos[1:]:
            need(a, roots_r)
        return None
    if prog == "find":
        bad = {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"}
        if any(a in bad for a in args):
            raise PermissionError("find의 -exec/-delete 등은 불가")
        for a in args:
            if a.startswith("-") or a in ("(", ")", "!"):
                break
            need(a, roots_r)
        return None
    if prog == "mkdir":
        for a in args:
            if not a.startswith("-"):
                need(a, roots_w, "점검 폴더(쓰기)")
        return None
    if prog in ("cp", "ditto"):
        pos = [a for a in args if not a.startswith("-")]
        if len(pos) < 2:
            raise PermissionError("cp는 `cp -R 원본 점검폴더/…` 형태만")
        need(pos[-1], roots_w, "점검 폴더(쓰기)")
        return None
    if prog == "unzip":
        if "-l" in args or "-Z" in args or "-v" in args:
            return None
        if "-d" not in args:
            raise PermissionError("unzip은 -l(목록) 또는 -d 점검폴더 로만")
        need(args[args.index("-d") + 1], roots_w, "점검 폴더(쓰기)")
        return None
    if prog == "tar":
        if any(a.startswith(("--to-command", "--use-compress", "--checkpoint", "-I")) for a in args):
            raise PermissionError("tar 외부 프로그램 옵션 불가")
        mode = (args[0].lstrip("-") if args else "")
        if "t" in mode:
            return None
        if "x" in mode and "-C" in args:
            need(args[args.index("-C") + 1], roots_w, "점검 폴더(쓰기)")
            return None
        raise PermissionError("tar는 -t(목록) 또는 -x … -C 점검폴더 로만")
    if prog == "gh":
        sub = args[0] if args else ""
        if sub == "api":
            if any(a in ("-X", "--method", "-f", "-F", "--field", "--raw-field", "--input") or
                   a.startswith(("--method=", "--field=", "--raw-field=", "--input=", "-f", "-F")) for a in args[1:]):
                raise PermissionError("gh api는 조회(GET)만")
            return None
        if sub == "search" or (sub == "repo" and args[1:2] == ["view"]):
            return None
        raise PermissionError("gh는 api 조회·search·repo view만")
    if prog == "git":
        i, gdir, has_hooks_off = 0, None, False
        while i < len(args) and args[i].startswith("-"):
            a = args[i]
            if a == "-C":
                gdir = args[i + 1]
                i += 2
            elif a == "-c":
                if args[i + 1] not in VET_GIT_C_OK:
                    raise PermissionError(f"git -c {args[i + 1]} 불가")
                has_hooks_off |= args[i + 1] == "core.hooksPath=/dev/null"
                i += 2
            elif a == "--no-pager":
                i += 1
            else:
                raise PermissionError(f"git 옵션 불가: {a}")
        sub = args[i] if i < len(args) else ""
        rest = args[i + 1:]
        if sub not in VET_GIT_SUB:
            raise PermissionError(f"git {sub} 불가 (조회·clone만)")
        if any(a.startswith(("--upload-pack", "--config", "--template", "--exec", "--ext-diff", "--output", "-u", "--recurse-submodules"))
               for a in rest):
            raise PermissionError("git 위험 옵션 불가")
        if sub == "clone":
            if not has_hooks_off:
                raise PermissionError("clone은 `git -c core.hooksPath=/dev/null -c protocol.file.allow=never -c core.symlinks=false clone …` 로만")
            pos, skip = [], False
            for a in rest:
                if skip:
                    skip = False
                elif a in ("--depth", "-b", "--branch", "--filter"):
                    skip = True
                elif not a.startswith("-"):
                    pos.append(a)
            if len(pos) != 2:
                raise PermissionError("clone은 주소와 점검폴더 대상을 적어 주세요")
            m = re.match(r"^https://([^/@:]+)/", pos[0])
            if not m or m.group(1) not in VET_HOSTS:
                raise PermissionError(f"clone 주소 불가: {pos[0]}")
            need(pos[1], roots_w, "점검 폴더(쓰기)")
            return None
        if gdir is not None:
            need(gdir, [vdir])
        elif not any(inside(os.path.realpath(cwd), x) for x in [vdir]):
            raise PermissionError("git 조회는 -C 점검폴더/src 로")
        return None
    if prog == "curl":
        valopts = {"-d", "--data", "--data-raw", "--data-binary", "-H", "--header", "-o", "--output", "-A", "-m",
                   "--max-time", "-w", "--connect-timeout", "--retry", "-X", "--request"}
        bad = {"-T", "--upload-file", "-F", "--form", "--form-string", "-K", "--config", "-O", "--remote-name",
               "-x", "--proxy", "--unix-socket", "-u", "--user", "--output-dir", "-b", "--cookie", "-c", "--cookie-jar"}
        i = 0
        while i < len(args):
            a = args[i]
            if a in bad or a.split("=", 1)[0] in bad:
                raise PermissionError(f"curl {a} 불가")
            if a in valopts:
                v = args[i + 1] if i + 1 < len(args) else ""
                if a in ("-d", "--data", "--data-raw", "--data-binary") and v.startswith("@"):
                    raise PermissionError("curl -d @파일(파일 내용 전송) 불가")
                if a in ("-o", "--output"):
                    need(v, roots_w, "점검 폴더(쓰기)")
                i += 2
                continue
            if a.startswith("-"):
                if not re.fullmatch(r"-[sSLfkvI]+|--(silent|show-error|location|fail|compressed|globoff|http1\.1|head)", a):
                    raise PermissionError(f"curl 옵션 불가: {a}")
                i += 1
                continue
            m = re.match(r"^https://([^/@:?#]+)", a)
            if not m or m.group(1) not in VET_HOSTS:
                raise PermissionError(f"curl 주소 불가(허용: GitHub·OSV·Scorecard 조회): {a}")
            i += 1
        return None
    if prog in ("python3", "python"):
        i = 0
        flags = []
        while i < len(args) and re.fullmatch(r"-[IBusE]+", args[i]):
            flags.append(args[i])
            i += 1
        if not any("I" in f for f in flags):
            raise PermissionError("python은 항상 -I")
        rest = args[i:]
        if rest[:1] == ["-c"]:
            code = rest[1] if len(rest) > 1 else ""
            if len(rest) > 2:
                raise PermissionError("python -c 뒤 인자 불가")
            for m in re.finditer(r"(?:^|[;\n])\s*(?:import\s+([\w., ]+)|from\s+(\w+)\s+import)", code):
                names = [x.strip().split(" ")[0] for x in (m.group(1) or m.group(2)).split(",")]
                if any(x not in PY_IMPORT_OK for x in names):
                    raise PermissionError(f"python -c 에서 쓸 수 없는 모듈: {names}")
            if PY_CODE_BAD.search(code):
                raise PermissionError("python -c 에서 실행·파일 쓰기 함수 불가 (읽어서 출력만)")
            return None
        if not rest:
            raise PermissionError("python 대화형 실행 불가")
        script = res(rest[0])
        sargs = rest[1:]
        if script == os.path.realpath(SCAN):
            for a in sargs:
                need(a, roots_w, "점검 폴더")
            return None
        if script == os.path.realpath(os.path.join(SK, "scripts", "install_verified.py")):
            if len(sargs) != 3:
                raise PermissionError("install_verified.py 인자 3개")
            need(sargs[0], roots_w)
            need(sargs[1], roots_w)
            dparent = os.path.dirname(res(sargs[2]))
            okp = {os.path.realpath(os.path.join(CL, x)) for x in ("skills", "agents", "commands")}
            okp |= {os.path.realpath(os.path.join(cwd, ".claude", x)) for x in ("skills", "agents", "commands")}
            if dparent not in okp:
                raise PermissionError("설치 위치는 ~/.claude/skills(agents·commands)/<이름> 만")
            return None
        if script == os.path.realpath(os.path.abspath(__file__)):
            sub = sargs[0] if sargs else ""
            if sub == "status" or sub == "vet-start":
                return None
            if sub == "vet-end":
                if "--discard" in sargs:
                    return None
                return ("ask", "점검 모드를 끄려고 합니다(받은 코드는 남겨 둠). 직접 요청하신 게 맞으면 승인하세요. "
                               "받은 코드가 필요 없으면 `vet-end <폴더> --discard`는 승인 없이 됩니다.")
            raise PermissionError(f"guard.py {sub} 불가")
        raise PermissionError(f"점검 모드에서는 이 스킬의 스크립트만 실행됩니다: {rest[0]}")
    if prog in ("osv-scanner", "gitleaks"):
        for a in args:
            if pathlike(a) and not a.startswith("-"):
                need(a, roots_r)
        return None
    if prog == "semgrep":
        if "--metrics=off" not in args:
            raise PermissionError("semgrep은 --metrics=off 로만")
        for a in args:
            if not a.startswith("-") and "/" in a and not a.startswith("p/"):
                need(a, roots_r)
        return None
    raise PermissionError(f"점검 모드에서 허용되지 않은 명령: {prog}")


def _find_vet_start(cmd):
    """실제로 실행되는 guard.py 의 vet-start 명령만 (따옴표 안 글자·echo 문자열·입력 본문은 제외)."""
    try:
        w = [v for k, v in tokenize(cmd) if k == "w"]
    except ValueError:
        return None
    for i in range(len(w) - 2):
        if w[i].endswith("guard.py") and w[i + 1] == "vet-start":
            return w[i + 2]
    return None


def cmd_vet_start(d):
    rd = vet_valid_dir(d)
    hit = [s for _, s in vet_states() if rd and s.get("dir") == rd and time.time() < s.get("expires", 0)]
    if hit:
        print(f"점검 모드 켜짐: {rd.replace(HOME, '~')} (최대 {time.strftime('%H:%M', time.localtime(hit[0]['expires']))}까지)")
    else:
        print("점검 모드가 켜지지 않았습니다. 감시 훅(PreToolUse)이 등록돼 있는지, 폴더가 임시 폴더 아래 vet-… 인지 확인하세요.")


def cmd_vet_end(d, discard):
    rd = vet_valid_dir(d)
    if not rd:
        sys.exit("중단: 임시 폴더 아래 vet-… 폴더만 지정할 수 있습니다.")
    n = 0
    for p, s in vet_states():
        if s.get("dir") == rd:
            os.remove(p)
            n += 1
    log(f"vet-mode 끔({'삭제' if discard else '보존'}): {rd.replace(HOME, '~')}")
    if discard and os.path.isdir(rd):
        import shutil
        shutil.rmtree(rd)
        print(f"점검 모드 끔 + 받은 코드 폴더 삭제: {rd}")
    else:
        print(f"점검 모드 끔 ({n}개 세션): {rd}")



def pretool():
    try:
        data = json.load(sys.stdin)
    except Exception:
        return
    tool = data.get("tool_name", "")
    ti = data.get("tool_input") or {}
    sid = data.get("session_id") or "nosession"
    cwd = data.get("cwd") or os.getcwd()
    vet = vet_load(sid)

    # 오토 모드에서도 끊기지 않게: 승인창(ask)은 기준선 변경 하나만 남기고,
    # 확실한 악성은 자동 차단(deny), 나머지는 기록만(note) — 스킬·설정 변경은 SessionStart 무결성 검사가 다시 잡는다.
    def decide(kind, reason):
        log(f"{kind} {tool}: {reason}")
        if kind == "deny":
            reason += " (꼭 필요하면 사용자가 직접 `! 명령`으로 실행하세요)"
        out({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                    "permissionDecision": kind,
                                    "permissionDecisionReason": "[스킬 보안 감시] " + reason}})

    def note(reason):
        log(f"note {tool}: {reason}")

    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        p = ti.get("file_path") or ti.get("notebook_path") or ""
        rp = os.path.realpath(os.path.expanduser(p))
        if rp in EXEMPT_WRITE:
            return
        full = rp if os.path.isabs(p) else os.path.realpath(os.path.join(cwd, p))
        if vet and not inside(full, vet["dir"]):
            decide("deny", f"[점검 모드] 외부 코드 점검 중에는 점검 폴더({vet['dir']}) 밖에 파일을 쓸 수 없습니다. "
                           "점검이 끝난 뒤(설치 또는 `guard.py vet-end <폴더> --discard`) 진행하세요.")
        if PROT_PATH.search(full.replace(HOME, "~")) or PROT_PATH.search(full):
            note(f"스킬·플러그인·훅·MCP 설정 파일 수정: {full.replace(HOME, '~')}")
        return

    if tool != "Bash":
        return
    cmd = ti.get("command") or ""

    # 이 스킬 자신의 스크립트 경로(guard.py·scan.py·install_verified.py)를 부르는 것은 스킬 폴더를 '건드리는' 것으로 보지 않음
    own = re.compile(r"(~|\$HOME|\$\{HOME\}|" + re.escape(HOME) + r")/\.claude/skills/skill-security-vetting/(hooks/guard|scripts/(scan|install_verified))\.py")
    touches = bool(PROT_PATH.search(own.sub("<이-스킬-스크립트>", cmd)))
    # 실제로 실행되는 부분만: heredoc 본문·따옴표 안 문자열을 걷어낸 명령
    bare = re.sub(r"<<-?\s*['\"]?(\w+)['\"]?.*?\n.*?\n\1\b", "<<HEREDOC", cmd, flags=re.S)
    bare = re.sub(r"'[^']*'|\"(\\.|[^\"\\])*\"", "''", bare)

    # 입력 본문(heredoc)은 받는 쪽이 셸(sh·bash·zsh)일 때만 실행되는 코드로 본다. cat·python3·tee 등에 넘기는 본문은 데이터.
    def _strip_data_heredoc(m):
        before = cmd[:m.start()].rsplit("\n", 1)[-1]
        return m.group(0) if re.search(r"\b(ba|z|da)?sh\s*(-s\s*)?$", before.strip()) else "<<HEREDOC"
    nohd = re.sub(r"<<-?\s*['\"]?(\w+)['\"]?.*?\n.*?\n\1\b", _strip_data_heredoc, cmd, flags=re.S)

    # 0) 점검 모드 켜기: vet-start 명령, 또는 임시 폴더의 vet-… 폴더로 받기 시작하면 자동으로 (이 세션만)
    if not vet:
        m = _find_vet_start(nohd)
        cand = m
        if not cand and FETCH_VERB.search(bare):
            m2 = VET_PATH.search(cmd)
            cand = m2.group(1) if m2 else None
        if cand:
            rd = vet_valid_dir(cand)
            if rd:
                vet = vet_start(sid, rd)
            elif m:
                decide("deny", "점검 폴더는 임시 폴더 아래 `vet-…` 이름이어야 합니다 (mktemp -d \"${TMPDIR:-/tmp}/vet-REPO-XXXXXX\").")

    # 1) 승인창: 감시 기준선 변경 + 외부 스킬 설치(설치하면서 기준선에 자동 등록되므로) — 둘 다 드물게만 뜸
    if BASELINE_CHANGE.search(cmd):
        decide("ask", "감시 기준선 변경입니다. 바뀐 스킬·설정을 확인하셨다면 승인하세요.")
    if re.search(r"python3?\b[^|;&\n]*install_verified\.py", cmd):
        if vet:
            r = None
            try:
                r = vet_check(cmd, cwd, vet["dir"])
            except Exception as e:
                r = ("deny", f"판단 중 오류: {e}")
            if r:
                decide("deny", "[점검 모드] " + r[1])
        decide("ask", "점검한 외부 스킬을 설치하고 감시 기준선에 등록합니다. 점검 결과를 보고 설치하기로 하셨다면 승인하세요.")
    # 2) 자동 차단: 확실한 악성
    if touches and FETCH_VERB.search(bare):
        decide("deny", "외부 코드를 스킬·플러그인·설정 폴더에 직접 받으려고 합니다. 격리 폴더에 받기 → 점검 → install_verified.py 절차로 진행하세요.")
    for i, (rx, desc) in enumerate(RUNTIME):
        if desc not in DENY_DESCS:
            continue
        if i == 0:
            hit = downloaded_code_runs(nohd)
        elif desc == "권한 확인 우회":
            hit = rx.search(bare)  # 설정 파일을 grep하는 것처럼 따옴표 안 글자는 제외
        else:
            hit = rx.search(nohd)
        if hit:
            decide("deny", f"위험한 명령이라 막았습니다: {desc}")
    # 2-1) 점검 모드: 허용 목록에 있는 명령만 (오토 모드와 상관없이)
    if vet:
        try:
            r = vet_check(cmd, cwd, vet["dir"])
        except Exception as e:
            r = ("deny", f"판단 중 오류: {e}")
        if r:
            kind, why = r
            msg = f"[점검 모드] {why}"
            if kind == "deny":
                msg += (" — 외부 코드를 점검하는 동안에는 읽기·점검 명령만 실행됩니다. "
                        "점검이 끝나면 설치(install_verified.py) 또는 `guard.py vet-end <폴더> --discard`로 끄세요"
                        f" (자동으로 꺼지는 시각 {time.strftime('%H:%M', time.localtime(vet['expires']))})")
            decide(kind, msg)
    # 3) 기록만: 스킬·설정 폴더 쓰기, 설치, 자동 실행 등록 등 (다음 세션 시작 때 무결성 검사가 확인)
    if touches and (WRITE_VERB.search(cmd) or "install_verified.py" in cmd or FETCH_VERB.search(cmd)):
        note("스킬·플러그인·훅·MCP 설정 폴더를 바꾸는 명령")
    if INSTALL_CMD.search(cmd):
        note("플러그인·스킬·MCP 서버 설치 명령")
    for rx, desc in RUNTIME[1:]:
        if desc not in DENY_DESCS and rx.search(cmd):
            note(f"주의 명령: {desc}")


# ------------------------------------------------------------------ SessionStart (무결성)


def file_hash(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tree(path, skip_state=False):
    files = {}
    if os.path.isfile(path):
        return {os.path.basename(path): file_hash(path)}
    for dp, dns, fns in os.walk(path, followlinks=False):
        dns[:] = [d for d in dns if d not in IGNORE_NAMES and not (skip_state and os.path.realpath(os.path.join(dp, d)) == STATE)]
        for fn in fns:
            full = os.path.join(dp, fn)
            if fn in IGNORE_NAMES or full in IGNORE_FILES:
                continue
            r = os.path.relpath(full, path)
            if os.path.islink(full):
                files[r] = "link:" + os.readlink(full)
            else:
                try:
                    files[r] = file_hash(full)
                except OSError:
                    files[r] = "unreadable"
    return files


def json_digest(path, pick):
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except Exception:
        return None
    sub = pick(d)
    if not sub:
        return None
    return {"(설정)": hashlib.sha256(json.dumps(sub, sort_keys=True, ensure_ascii=False).encode()).hexdigest()}


def targets(cwd):
    t = {}
    sk = os.path.join(CL, "skills")
    if os.path.isdir(sk):
        for n in sorted(os.listdir(sk)):
            p = os.path.join(sk, n)
            if n == "synced" and os.path.isdir(p):
                for acct in os.listdir(p):
                    ap = os.path.join(p, acct)
                    if os.path.isdir(ap):
                        for s in os.listdir(ap):
                            if os.path.isdir(os.path.join(ap, s)):
                                t[f"skill:synced/{s}"] = ("dir", os.path.join(ap, s))
            elif os.path.isdir(p) or os.path.islink(p):
                t[f"skill:{n}"] = ("dir", p)
    for sub in ("agents", "commands"):
        p = os.path.join(CL, sub)
        if os.path.isdir(p):
            t[f"user:{sub}"] = ("dir", p)
    cache = os.path.join(CL, "plugins", "cache")
    if os.path.isdir(cache):
        for mk in os.listdir(cache):
            for pl in os.listdir(os.path.join(cache, mk)) if os.path.isdir(os.path.join(cache, mk)) else []:
                pp = os.path.join(cache, mk, pl)
                if os.path.isdir(pp):
                    t[f"plugin:{pl}@{mk}"] = ("dir", pp)
    mks = os.path.join(CL, "plugins", "marketplaces")
    if os.path.isdir(mks):
        for mk in os.listdir(mks):
            if os.path.isdir(os.path.join(mks, mk)):
                t[f"marketplace:{mk}"] = ("dir", os.path.join(mks, mk))
    # 훅·권한·MCP 설정(값은 저장하지 않고 해시만)
    pick_hooks = lambda d: {k: d.get(k) for k in ("hooks", "permissions", "enabledPlugins", "extraKnownMarketplaces",
                                                  "enableAllProjectMcpServers", "enabledMcpjsonServers", "statusLine",
                                                  "apiKeyHelper", "sandbox", "disableAllHooks", "disableSkillShellExecution",
                                                  "skipDangerousModePermissionPrompt", "env") if k in d}
    for name in ("settings.json", "settings.local.json"):
        t[f"config:~/.claude/{name}"] = ("json", os.path.join(CL, name), pick_hooks)
    t["config:~/.claude.json mcpServers"] = ("json", os.path.join(HOME, ".claude.json"),
                                             lambda d: {"g": d.get("mcpServers"),
                                                        "p": {k: v.get("mcpServers") for k, v in (d.get("projects") or {}).items() if v.get("mcpServers")}})
    # 홈 폴더에서 열면 cwd/.claude 가 ~/.claude 자체라 위 항목과 중복됨 → 프로젝트 항목으로 다시 세지 않음
    if cwd and os.path.realpath(cwd) == os.path.realpath(HOME):
        cwd = None
    if cwd and os.path.isdir(os.path.join(cwd, ".claude")):
        for sub in ("skills", "commands", "agents", "hooks"):
            p = os.path.join(cwd, ".claude", sub)
            if os.path.isdir(p):
                t[f"project:{cwd.replace(HOME, '~')}/.claude/{sub}"] = ("dir", p)
        for name in ("settings.json", "settings.local.json"):
            t[f"config:{cwd.replace(HOME, '~')}/.claude/{name}"] = ("json", os.path.join(cwd, ".claude", name), pick_hooks)
    if cwd and os.path.isfile(os.path.join(cwd, ".mcp.json")):
        t[f"config:{cwd.replace(HOME, '~')}/.mcp.json"] = ("dir", os.path.join(cwd, ".mcp.json"))
    return t


def snapshot(cwd, only=None):
    snap = {}
    for key, spec in targets(cwd).items():
        if only and key not in only:
            continue
        if spec[0] == "dir":
            if not os.path.exists(spec[1]):
                continue
            snap[key] = {"path": spec[1], "files": tree(spec[1], skip_state=(spec[1] == SK))}
        else:
            if not os.path.exists(spec[1]):
                continue
            d = json_digest(spec[1], spec[2])
            if d is not None:
                snap[key] = {"path": spec[1], "files": d}
    return snap


def load_baseline():
    try:
        with open(BASELINE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_baseline(b):
    os.makedirs(STATE, exist_ok=True)
    tmp = BASELINE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(b, f, ensure_ascii=False)
    os.replace(tmp, BASELINE)


def diff(base, cur):
    changes = []
    for k, v in cur.items():
        b = base["items"].get(k)
        if b is None:
            changes.append(("새로 생김", k, v["path"], sorted(v["files"])))
        elif b["files"] != v["files"]:
            ch = sorted(set(f for f in set(b["files"]) | set(v["files"]) if b["files"].get(f) != v["files"].get(f)))
            changes.append(("바뀜", k, v["path"], ch))
    for k, b in base["items"].items():
        if k not in cur and (not k.startswith(("project:", "config:")) or k.startswith("config:~/.claude")):
            changes.append(("사라짐", k, b["path"], []))
    return changes


def pending_paths(key):
    safe = re.sub(r"[^A-Za-z0-9가-힣._-]", "_", key)[:80]
    return os.path.join(PENDING, safe + ".md"), os.path.join(PENDING, safe + ".json")


def scan_dir(key, path):
    os.makedirs(PENDING, exist_ok=True)
    md, js = pending_paths(key)
    try:
        subprocess.run([sys.executable, "-I", SCAN, path, md, js], capture_output=True, timeout=12, cwd=STATE)
        with open(js, encoding="utf-8") as f:
            c = json.load(f)["건수"]
        return c, md
    except Exception as e:
        return None, str(e)


def session():
    try:
        data = json.load(sys.stdin)
    except Exception:
        data = {}
    cwd = data.get("cwd") or os.getcwd()
    base = load_baseline()
    if base is None:
        out({"systemMessage": "[스킬 보안 감시] 기준선이 없습니다. 'guard.py baseline-init'으로 처음 1회 등록이 필요합니다."})
    cur = snapshot(cwd)
    # 이 폴더의 프로젝트 설정이 기준선에 아직 없으면(처음 여는 프로젝트) 새로 생김으로 보고
    changes = diff(base, cur)
    if not changes:
        return
    lines, ctx = [], []
    t0 = time.time()
    for kind, key, path, files in changes[:15]:
        sev = ""
        if kind != "사라짐" and os.path.isdir(path) and not key.startswith("marketplace:") and time.time() - t0 > 15:
            sev = " → 시간 초과로 스캔 생략(직접 점검 필요)"
        elif kind != "사라짐" and os.path.isdir(path) and not key.startswith("marketplace:"):
            c, md = scan_dir(key, path)
            if c:
                sev = f" → 스캔 위험 {c['위험']}·주의 {c['주의']} ({md.replace(HOME, '~')})"
        fl = ", ".join(files[:4]) + (f" 외 {len(files) - 4}개" if len(files) > 4 else "")
        lines.append(f"- {kind}: {key}{(' [' + fl + ']') if fl and kind == '바뀜' else ''}{sev}")
    more = f"\n- …외 {len(changes) - 15}건" if len(changes) > 15 else ""
    msg = "[스킬 보안 감시] 점검 기준선과 다른 항목이 있습니다:\n" + "\n".join(lines) + more
    log("session changes: " + "; ".join(f"{k}:{key}" for k, key, *_ in changes))
    out({"systemMessage": msg,
         "hookSpecificOutput": {"hookEventName": "SessionStart",
                                "additionalContext": msg + "\n\n사용자에게 이 목록을 먼저 알리고, 바뀐 항목은 skill-security-vetting 4단계(직접 읽기)로 확인한 뒤 사용자가 승인하면 `python3 -I ~/.claude/skills/skill-security-vetting/hooks/guard.py accept <키>`로 기준선을 갱신하세요. 확인 전에는 해당 스킬·플러그인을 쓰지 마세요."}})


def cmd_baseline_init(cwds):
    items = {}
    for c in cwds or [os.getcwd()]:
        items.update(snapshot(c))
    save_baseline({"created": time.strftime("%Y-%m-%d %H:%M:%S"), "items": items, "tracked_cwds": cwds})
    print(f"기준선 저장: 항목 {len(items)}개 → {BASELINE}")


def cmd_accept(keys, cwd):
    base = load_baseline()
    if base is None:
        sys.exit("기준선이 없습니다. baseline-init 먼저.")
    cur = snapshot(cwd)
    if keys == ["all"]:
        keys = [k for _, k, _, _ in diff(base, cur)]
    for k in keys:
        if k in cur:
            base["items"][k] = cur[k]
            print("승인·갱신:", k)
        elif k in base["items"]:
            del base["items"][k]
            print("삭제 반영:", k)
        else:
            print("해당 없음:", k)
            continue
        # 확인을 마친 항목의 자동 스캔 결과는 더 이상 대기 상태가 아니므로 정리
        for pth in pending_paths(k):
            if os.path.isfile(pth):
                os.remove(pth)
    save_baseline(base)
    log("accept " + ",".join(keys))


def cmd_status(cwd):
    base = load_baseline()
    if base is None:
        print("기준선 없음")
        return
    ch = diff(base, snapshot(cwd))
    for kind, key, path, files in ch:
        print(kind, key, ", ".join(files[:6]))
    if not ch:
        print("변경 없음")


if __name__ == "__main__":
    a = sys.argv[1:] or [""]
    if a[0] == "pretool":
        pretool()
    elif a[0] == "session":
        session()
    elif a[0] == "baseline-init":
        cmd_baseline_init([os.path.realpath(x) for x in a[1:]])
    elif a[0] == "accept":
        cmd_accept(a[1:], os.getcwd())
    elif a[0] == "status":
        cmd_status(os.getcwd())
    elif a[0] == "vet-start" and len(a) >= 2:
        cmd_vet_start(a[1])
    elif a[0] == "vet-end" and len(a) >= 2:
        cmd_vet_end(a[1], "--discard" in a[2:])
    else:
        print(__doc__)
