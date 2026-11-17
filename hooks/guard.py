#!/usr/bin/env python3
"""
skill-security-vetting 자동 감시 훅.

  guard.py pretool        PreToolUse 훅(stdin JSON). 스킬·플러그인·설정 폴더 쓰기 감시 + 위험 명령 확인 요청
  guard.py session        SessionStart 훅. 스킬·플러그인·훅·MCP 설정이 기준선과 달라졌는지 검사
  guard.py baseline-init  현재 상태를 기준선으로 저장(처음 1회, 사용자 승인 후)
  guard.py accept <키|all> 변경을 확인·승인한 뒤 기준선 갱신 (Claude가 실행하면 항상 승인창이 뜸)
  guard.py status         기준선과 현재 차이만 출력

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
FETCH_VERB = re.compile(r"\b(git\s+clone|gh\s+repo\s+clone|curl|wget|unzip|tar\s+-?[a-zA-Z]*x|svn\s+(checkout|export)|degit)\b")
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


def pretool():
    try:
        data = json.load(sys.stdin)
    except Exception:
        return
    tool = data.get("tool_name", "")
    ti = data.get("tool_input") or {}

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
        cwd = data.get("cwd") or os.getcwd()
        full = rp if os.path.isabs(p) else os.path.realpath(os.path.join(cwd, p))
        if PROT_PATH.search(full.replace(HOME, "~")) or PROT_PATH.search(full):
            note(f"스킬·플러그인·훅·MCP 설정 파일 수정: {full.replace(HOME, '~')}")
        return

    if tool != "Bash":
        return
    cmd = ti.get("command") or ""

    touches = bool(PROT_PATH.search(cmd))
    # 실제로 실행되는 부분만: heredoc 본문·따옴표 안 문자열을 걷어낸 명령
    bare = re.sub(r"<<-?\s*['\"]?(\w+)['\"]?.*?\n.*?\n\1\b", "<<HEREDOC", cmd, flags=re.S)
    bare = re.sub(r"'[^']*'|\"(\\.|[^\"\\])*\"", "''", bare)

    # 입력 본문(heredoc)은 받는 쪽이 셸(sh·bash·zsh)일 때만 실행되는 코드로 본다. cat·python3·tee 등에 넘기는 본문은 데이터.
    def _strip_data_heredoc(m):
        before = cmd[:m.start()].rsplit("\n", 1)[-1]
        return m.group(0) if re.search(r"\b(ba|z|da)?sh\s*(-s\s*)?$", before.strip()) else "<<HEREDOC"
    nohd = re.sub(r"<<-?\s*['\"]?(\w+)['\"]?.*?\n.*?\n\1\b", _strip_data_heredoc, cmd, flags=re.S)

    # 1) 승인창: 감시 기준선 변경만 (악성 스킬이 Claude를 속여 스스로 승인하는 것 방지, 드물게만 뜸)
    if BASELINE_CHANGE.search(cmd):
        decide("ask", "감시 기준선 변경입니다. 바뀐 스킬·설정을 확인하셨다면 승인하세요.")
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
    else:
        print(__doc__)
