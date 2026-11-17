#!/usr/bin/env python3
"""
skill-security-vetting 정적 스캐너 (읽기 전용, 표준 라이브러리만 사용).

대상 폴더의 파일을 '읽기만' 하고 아무것도 실행하지 않는다.
반드시 `python3 -I scan.py <대상폴더> <리포트.md> <결과.json>` 형태로,
이 스크립트가 있는 폴더(신뢰)에서 대상 폴더(비신뢰)를 인자로 넘겨 실행한다.
"""
import json
import os
import re
import stat
import sys
import hashlib
import unicodedata

HIGH, MED, LOW = "위험", "주의", "참고"
SEV_ORDER = {HIGH: 0, MED: 1, LOW: 2}

SKIP_DIRS = {".git"}
TEXT_LIMIT = 2_000_000  # 2MB 넘는 텍스트는 내용 스캔 생략(목록에는 표시)
BINARY_EXT = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".pyc", ".pyo",
    ".class", ".jar", ".wasm", ".node", ".app", ".dmg", ".pkg", ".deb",
    ".rpm", ".msi", ".scpt", ".command", ".zip", ".tar", ".gz", ".tgz",
    ".7z", ".rar", ".xz", ".bz2",
}

# ---------------------------------------------------------------- 패턴
# (카테고리, 심각도, 정규식, 설명)
LINE_RULES = [
    # 원격 코드 즉시 실행
    ("원격실행", HIGH, r"(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", "다운로드한 스크립트를 바로 셸로 실행"),
    ("원격실행", HIGH, r"(curl|wget)\b[^|\n]*\|\s*(python3?|node|perl|ruby)\b", "다운로드한 코드를 바로 인터프리터로 실행"),
    ("원격실행", HIGH, r"(ba|z)?sh\s+<\(\s*(curl|wget)", "프로세스 치환으로 원격 스크립트 실행"),
    ("원격실행", HIGH, r"(Invoke-Expression|\biex\b)\s*\(?\s*(\(|\$)?\s*(iwr|Invoke-WebRequest|New-Object\s+Net\.WebClient)", "PowerShell 원격 실행"),
    ("원격실행", MED, r"osascript\s+-e", "AppleScript 실행(권한 팝업 우회·자동화 가능)"),
    # 파괴적 명령
    ("파괴적", HIGH, r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(/|~|\$HOME|\"\$HOME|\*)(\s|$|/|\")", "루트/홈 전체 삭제 가능"),
    ("파괴적", HIGH, r"\b(mkfs|diskutil\s+erase|dd\s+if=)", "디스크 포맷/덮어쓰기"),
    ("권한상승", MED, r"(^|[\s;&|`(])sudo\s", "관리자 권한 요구"),
    ("권한상승", MED, r"chmod\s+(-R\s+)?(777|a\+rwx|\+s|u\+s)", "과도한 권한/setuid 부여"),
    ("권한상승", MED, r"xattr\s+-[a-z]*d\s+com\.apple\.quarantine", "macOS 격리(Gatekeeper) 해제"),
    # 지속성(재부팅 후에도 남는 변경)·설정 변조
    ("지속성", HIGH, r"LaunchAgents|LaunchDaemons|launchctl\s+(load|bootstrap|submit)", "자동 실행 등록"),
    ("지속성", HIGH, r"\bcrontab\b", "예약 작업 등록"),
    ("지속성", HIGH, r"(>>?|tee\s+-a|open\(|write).{0,40}(\.zshrc|\.bashrc|\.bash_profile|\.zprofile|\.profile|\.zshenv)", "셸 시작 파일 수정"),
    ("설정변조", HIGH, r"\.claude/(settings(\.local)?\.json|hooks)|~/\.claude\.json", "Claude Code 설정/훅 수정 시도"),
    ("설정변조", HIGH, r"dangerously-skip-permissions|bypassPermissions|\"defaultMode\"\s*:\s*\"(bypassPermissions|acceptEdits)\"", "권한 확인 우회"),
    ("설정변조", MED, r"(CLAUDE\.md|MEMORY\.md|/memory/)", "지시문/메모리 파일 언급(수정 시도인지 확인)"),
    ("설정변조", MED, r"\bdefaults\s+write\b|\bspctl\s+--master-disable", "macOS 시스템 설정 변경"),
    ("설정변조", MED, r"git\s+config\s+--global|core\.hooksPath|\.git/hooks", "git 전역 설정/훅 변경"),
    # 민감 정보 읽기
    ("민감정보", HIGH, r"\.ssh(/|\b)|id_rsa|id_ed25519|authorized_keys", "SSH 키 접근"),
    ("민감정보", HIGH, r"\.aws/credentials|\.config/gcloud|\.azure/|\.kube/config|\.docker/config\.json", "클라우드 자격증명 접근"),
    ("민감정보", HIGH, r"security\s+(find|dump)-(generic|internet)-password|dump-keychain|Library/Keychains", "macOS 키체인 접근"),
    ("민감정보", HIGH, r"(Login Data|Cookies|Local State|Web Data)['\"/]|Application Support/(Google/Chrome|BraveSoftware|Firefox|Arc)", "브라우저 비밀번호/쿠키 접근"),
    ("민감정보", HIGH, r"\.git-credentials|\.netrc|gh\s+auth\s+token|\.config/gh/hosts", "git/GitHub 토큰 접근"),
    ("민감정보", MED, r"(^|[/'\"\s])\.env(\.[a-z]+)?(['\"\s]|$)|os\.environ\b|process\.env\b|printenv|\benv\s*$", "환경변수/.env 읽기(어디로 보내는지 확인)"),
    ("민감정보", MED, r"\.npmrc|\.pypirc|\.pgpass|wallet\.dat|Exodus|MetaMask|\.electrum", "토큰/지갑 파일 접근"),
    # 외부 유출 경로
    ("유출경로", HIGH, r"discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services", "메신저 웹훅(대표적 유출 통로)"),
    ("유출경로", HIGH, r"webhook\.site|requestbin|pipedream\.net|beeceptor|interact\.sh|oast\.(fun|me|pro|live)|burpcollaborator|canarytokens", "요청 수집 서비스(유출 확인용)"),
    ("유출경로", HIGH, r"pastebin\.com|paste\.ee|hastebin|transfer\.sh|file\.io|0x0\.st|temp\.sh|anonfiles", "익명 업로드/붙여넣기 서비스"),
    ("유출경로", HIGH, r"/dev/tcp/|\bnc\s+(-[a-z]*e|.*\s-e\s)|ncat\s.*-e|socat\s.*exec", "리버스 셸"),
    ("유출경로", MED, r"https?://(\d{1,3}\.){3}\d{1,3}", "IP 주소 직접 접속(도메인 없는 서버)"),
    ("유출경로", MED, r"ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|serveo\.net|loca\.lt", "임시 터널 주소"),
    ("유출경로", MED, r"\b(nslookup|dig|host)\s+[^\n]*\$\(", "DNS로 데이터 유출 가능 패턴"),
    # 동적 실행
    ("동적실행", MED, r"\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(|__import__\s*\(|\bcompile\s*\(", "문자열을 코드로 실행"),
    ("동적실행", MED, r"subprocess\.[a-zA-Z_]+\([^)]*shell\s*=\s*True|os\.system\s*\(|os\.popen\s*\(|child_process|execSync|spawnSync", "셸 명령 실행"),
    ("동적실행", MED, r"pickle\.loads?|marshal\.loads|yaml\.load\s*\((?![^)]*SafeLoader)|ctypes\.|dlopen", "안전하지 않은 역직렬화/네이티브 로드"),
    # 난독화
    ("난독화", HIGH, r"(base64\s+(-d|--decode|-D)|b64decode|atob\s*\(|Buffer\.from\([^)]*['\"]base64)[^\n]{0,120}(\|\s*(ba|z)?sh|exec|eval|Function)", "디코딩 후 실행"),
    ("난독화", MED, r"base64\s+(-d|--decode|-D)|b64decode|atob\s*\(|fromCharCode|codecs\.decode\([^)]*rot", "인코딩된 내용 풀기"),
    ("난독화", MED, r"(\\x[0-9a-fA-F]{2}){12,}|(\\u[0-9a-fA-F]{4}){8,}", "긴 이스케이프 문자열"),
    ("난독화", MED, r"[A-Za-z0-9+/]{200,}={0,2}", "긴 base64 덩어리"),
    # 실행 중 원격 지시 (rug pull)
    ("원격지시", MED, r"raw\.githubusercontent\.com|gist\.github(usercontent)?\.com|pastebin|\bjsdelivr\b.*\.md", "외부 원문 주소(실행 중 내용 바꿔치기 가능)"),
    ("원격지시", HIGH, r"(?i)(fetch|download|curl|wget|read|load|가져|불러|읽어)[^\n]{0,60}(instruction|prompt|rules|SKILL|지시|규칙)[^\n]{0,160}(follow|execute|따르|실행)", "외부에서 지시를 받아 따르게 함"),
    # 프롬프트 인젝션(영/한)
    ("인젝션", HIGH, r"(?i)ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|system)\s+(instructions|prompts?|rules|messages)", "이전 지시 무시 유도"),
    ("인젝션", HIGH, r"(?i)disregard\s+(all\s+|any\s+)?(previous|prior|above|your)\s|forget\s+(all\s+)?(your|previous)\s+(instructions|rules)", "이전 지시 무시 유도"),
    ("인젝션", HIGH, r"(?i)(do\s+not|don't|never)\s+(tell|inform|mention|reveal|show|notify)\s+(this\s+)?(to\s+)?(the\s+)?user|without\s+(asking|telling|notifying|informing)\s+(the\s+)?user", "사용자에게 숨기기"),
    ("인젝션", HIGH, r"(?i)\b(silently|secretly|covertly|quietly)\b\s+(run|execute|send|upload|install|copy|delete|modify)", "몰래 실행 지시"),
    ("인젝션", MED, r"(?i)you\s+are\s+now\s|new\s+system\s+prompt|<\s*/?\s*system\s*>|\[\s*SYSTEM\s*\]|developer\s+mode|jailbreak", "역할/시스템 프롬프트 바꿔치기"),
    ("인젝션", HIGH, r"(사용자|유저)(에게|한테)\s*(알리지|말하지|보여주지|묻지)\s*(마|말|않)|이전\s*(지시|명령|규칙)[을를]?\s*(무시|잊)|몰래\s*(실행|전송|보내|설치|복사|삭제|수정|진행|업로드)|(확인|승인|동의)\s*(없이(?!는)|받지\s*말고|생략)(?![^\n]{0,60}(않|말|금지|안\s*된|안\s*함|위반|불법|다가|해서는))", "사용자 몰래/승인 우회 지시(한글)"),
    # MCP 도구 설명 오염(tool poisoning)·점검자 속이기
    ("인젝션", MED, r"(?i)<\s*(IMPORTANT|CRITICAL|INSTRUCTIONS?)\s*>|before\s+using\s+this\s+tool|(pass|include|send)\s+(the\s+)?(full\s+)?(contents?|text)\s+of\s+[~/.]", "도구 설명 속 숨은 지시(tool poisoning)"),
    ("인젝션", HIGH, r"(?i)(this|the)\s+(skill|file|code|repo)\s+(has\s+been|was|is)\s+(already\s+)?(audited|verified|reviewed|approved)\s+(as\s+)?(safe|secure)|보안\s*점검[을를]?\s*(이미\s*)?(통과|완료)(했|된|됨)", "점검자 속이기(이미 검증됐다는 주장)"),
    # 데이터 유출 우회 경로
    ("유출경로", MED, r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)=\s]+=[^)]*\)", "마크다운 이미지 주소에 데이터를 붙여 보내는 형태"),
    ("유출경로", MED, r"https?://[^\s/]*xn--", "퓨니코드 도메인(비슷하게 생긴 가짜 도메인)"),
    ("유출경로", HIGH, r"https?://[A-Za-z0-9.\-]*[^\x00-\x7F\s][^\s/`'\")<>:]*\.[A-Za-z]{2,}", "URL 도메인에 영문 외 문자(동형문자 도메인)"),
    ("민감정보", MED, r"\bpbpaste\b|NSPasteboard|clipboard\.(read|get)|pyperclip\.paste", "클립보드 읽기"),
    ("민감정보", HIGH, r"\bscreencapture\b|imagesnap|avfoundation|CGWindowListCreateImage|tccutil|TCC\.db", "화면·카메라·개인정보 보호 설정 접근"),
    ("원격실행", HIGH, r"osascript[^\n]*(keystroke|key\s+code|System\s+Events)|tell\s+application\s+\"System Events\"", "키보드 입력 흉내(자동 조작)"),
    # 분석 회피·시한폭탄
    ("분석회피", MED, r"\b(GITHUB_ACTIONS|CODESPACES|CI)\b['\"]?\s*(\]|\)|in\s+os\.environ)|VirtualBox|VMware|sysctl\s+-n\s+hw\.model|is_sandbox|sandbox-exec", "점검·가상환경인지 감지(점검 때만 얌전한 코드)"),
    ("분석회피", LOW, r"(datetime|date)\.(now|today)\(\)[^\n]{0,40}[<>]=?\s*(datetime|date)\(\s*20\d\d", "특정 날짜 이후 동작(시한폭탄 가능)"),
    ("유출경로", LOW, r"(0\.0\.0\.0|http\.server|SimpleHTTPRequestHandler|createServer\()", "로컬 서버 열기(외부 접속 허용 여부 확인)"),
]
LINE_RULES = [(c, s, re.compile(p), d) for c, s, p, d in LINE_RULES]

SECRET_RULES = [
    (r"sk-(ant-|proj-)?[A-Za-z0-9_\-]{20,}", "OpenAI/Anthropic 키 형태"),
    (r"AIza[0-9A-Za-z_\-]{35}", "Google API 키 형태"),
    (r"gh[pousr]_[A-Za-z0-9]{36,}", "GitHub 토큰 형태"),
    (r"xox[baprs]-[A-Za-z0-9\-]{10,}", "Slack 토큰 형태"),
    (r"AKIA[0-9A-Z]{16}", "AWS 키 형태"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "개인키 블록"),
    (r"\b\d{8,10}:AA[0-9A-Za-z_\-]{33}\b", "텔레그램 봇 토큰 형태"),
]
SECRET_RULES = [(re.compile(p), d) for p, d in SECRET_RULES]

# 열기/설치만 해도 자동 실행될 수 있는 파일
AUTO_EXEC_FILES = {
    ".envrc": (HIGH, "direnv: 폴더에 들어가기만 해도 실행"),
    ".claude/settings.json": (HIGH, "이 폴더에서 Claude Code를 열면 훅·권한이 적용됨"),
    ".claude/settings.local.json": (HIGH, "이 폴더에서 Claude Code를 열면 훅·권한이 적용됨"),
    ".mcp.json": (HIGH, "MCP 서버 자동 등록(임의 프로그램 실행)"),
    ".vscode/tasks.json": (MED, "VS Code: runOn folderOpen이면 폴더만 열어도 실행"),
    ".vscode/settings.json": (MED, "VS Code 설정(터미널·인터프리터 경로 바꿔치기 가능)"),
    ".devcontainer/devcontainer.json": (MED, "컨테이너 postCreate 명령 실행"),
    ".gitmodules": (MED, "서브모듈: 다른 저장소 코드가 딸려옴"),
    ".gitattributes": (LOW, "filter/smudge·LFS 설정 확인"),
    ".npmrc": (MED, "npm 레지스트리 바꿔치기 가능"),
    "pip.conf": (MED, "pip 인덱스 바꿔치기 가능"),
    "setup.py": (MED, "pip 설치 시 임의 코드 실행"),
    "Makefile": (LOW, "make 실행 시 명령 확인 필요"),
    "Dockerfile": (LOW, "빌드 명령 확인 필요"),
    ".claude-plugin/plugin.json": (MED, "플러그인 매니페스트(훅·MCP 포함 가능)"),
    ".claude-plugin/marketplace.json": (MED, "마켓플레이스: 다른 저장소 플러그인을 끌어올 수 있음"),
    "hooks/hooks.json": (HIGH, "플러그인 훅(도구 실행 때마다 자동 실행)"),
    # AI 에이전트가 폴더를 열면 자동으로 읽는 지시 파일
    "CLAUDE.md": (MED, "이 폴더에서 Claude를 열면 자동으로 읽는 지시문"),
    "AGENTS.md": (MED, "AI 에이전트 자동 지시문"),
    "GEMINI.md": (MED, "AI 에이전트 자동 지시문"),
    ".cursorrules": (MED, "Cursor 자동 지시문"),
    ".windsurfrules": (MED, "Windsurf 자동 지시문"),
    ".github/copilot-instructions.md": (MED, "Copilot 자동 지시문"),
    # 파이썬: import·실행만 해도 자동 실행
    "sitecustomize.py": (HIGH, "파이썬 시작 시 자동 실행"),
    "usercustomize.py": (HIGH, "파이썬 시작 시 자동 실행"),
    "conftest.py": (MED, "pytest 실행 시 자동 실행"),
    # JS 패키지 매니저: 설치 시 자동 실행
    ".pnpmfile.cjs": (HIGH, "pnpm install 시 자동 실행"),
    ".yarnrc.yml": (MED, "yarnPath면 yarn 실행 시 임의 JS 실행"),
    "binding.gyp": (MED, "npm install 시 네이티브 빌드"),
    "bunfig.toml": (LOW, "bun 설정(preload 스크립트 확인)"),
    # git·개발 도구 훅
    ".pre-commit-config.yaml": (MED, "커밋할 때 외부 저장소 훅 실행"),
    ".husky/pre-commit": (MED, "커밋할 때 자동 실행"),
    "lefthook.yml": (MED, "git 훅 자동 실행"),
    "mise.toml": (MED, "mise: 폴더 진입 시 hooks/env 실행 가능"),
    ".mise.toml": (MED, "mise: 폴더 진입 시 hooks/env 실행 가능"),
    ".tool-versions": (LOW, "asdf/mise 도구 버전(플러그인 설치 유발)"),
    "justfile": (LOW, "just 실행 시 명령 확인 필요"),
    "Taskfile.yml": (LOW, "task 실행 시 명령 확인 필요"),
    "build.rs": (MED, "cargo build 시 자동 실행"),
    ".cargo/config.toml": (MED, "cargo 실행 경로·러너 바꿔치기"),
    ".idea/workspace.xml": (LOW, "JetBrains 실행 구성"),
}

# 숨은 유니코드
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}
ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x180E, 0x00AD}
TAGS = range(0xE0000, 0xE0080)
VARIATION_SUPP = range(0xE0100, 0xE01F0)


def rel(root, p):
    return os.path.relpath(p, root)


def is_binary(path, head):
    if os.path.splitext(path)[1].lower() in BINARY_EXT:
        return True
    return b"\x00" in head


def magic_kind(head):
    if head.startswith(b"\x7fELF"):
        return "ELF 실행파일"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf"):
        return "Mach-O 실행파일(macOS)"
    if head.startswith(b"MZ"):
        return "Windows 실행파일"
    if head.startswith(b"PK\x03\x04"):
        return "ZIP 압축"
    if head.startswith(b"#!"):
        return "스크립트(shebang)"
    return None


def scripts_of(name):
    return {
        "Cyrillic": "CYRILLIC" in name,
        "Greek": "GREEK" in name,
        "Latin": "LATIN" in name,
    }


def mixed_script_tokens(line):
    out = []
    for tok in re.findall(r"[^\W\d_]{3,}", line):
        kinds = set()
        for ch in tok:
            try:
                n = unicodedata.name(ch)
            except ValueError:
                continue
            for k, v in scripts_of(n).items():
                if v:
                    kinds.add(k)
        if "Latin" in kinds and (kinds & {"Cyrillic", "Greek"}):
            out.append(tok)
    return out


def scan_hidden_unicode(text):
    """(줄번호, 종류, 코드포인트목록) 반환"""
    hits = []
    for i, line in enumerate(text.splitlines(), 1):
        found = {}
        for j, ch in enumerate(line):
            cp = ord(ch)
            if cp == 0xFEFF and i == 1 and j == 0:
                continue  # 파일 맨 앞 BOM은 정상
            kind = None
            if cp in BIDI:
                kind = "양방향 제어문자(Trojan Source)"
            elif cp in TAGS:
                k = j
                while k > 0 and ord(line[k - 1]) in TAGS:
                    k -= 1
                if k > 0 and ord(line[k - 1]) == 0x1F3F4:
                    continue  # 🏴 지역 깃발 이모지(정상)
                kind = "유니코드 태그문자(AI에게 보이지 않는 지시 숨김)"
            elif cp in VARIATION_SUPP:
                kind = "변형 선택자(데이터 숨김 가능)"
            elif cp in ZERO_WIDTH:
                kind = "폭 없는 문자"
            elif ch == "\x1b":
                kind = "ANSI 이스케이프(터미널 표시 조작)"
            if kind:
                found.setdefault(kind, []).append(f"U+{cp:04X}")
        for kind, cps in found.items():
            hits.append((i, kind, cps))
    return hits


def decode_tag_payload(text):
    text = re.sub("\U0001F3F4[\U000E0020-\U000E007F]+", "", text)  # 깃발 이모지 제외
    s ="".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)
    return s[:300]


def parse_frontmatter(text):
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    return text[3:end]


POPULAR = {
    "PyPI": ["requests", "numpy", "pandas", "urllib3", "setuptools", "openai", "anthropic", "pillow", "beautifulsoup4",
             "selenium", "playwright", "python-dotenv", "pyyaml", "httpx", "aiohttp", "flask", "django", "fastapi",
             "boto3", "colorama", "cryptography", "jinja2", "matplotlib", "scipy", "tqdm", "click", "rich", "pydantic"],
    "npm": ["lodash", "express", "react", "axios", "chalk", "commander", "dotenv", "typescript", "puppeteer",
            "playwright", "openai", "@anthropic-ai/sdk", "node-fetch", "moment", "request", "colors", "yargs",
            "discord.js", "electron", "webpack", "vite", "next", "uuid", "debug", "cross-env", "eslint"],
}


def edit_distance(a, b):
    if abs(len(a) - len(b)) > 2:
        return 9
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def typosquat(eco, name):
    n = name.lower().replace("_", "-")
    for p in POPULAR.get(eco, []):
        if n != p and edit_distance(n, p) <= (1 if len(p) <= 5 else 2):
            return p
    return None


def check_dependencies(root, relpath, text, add):
    name = os.path.basename(relpath)
    deps = []
    if name == "package.json":
        try:
            pj = json.loads(text)
        except Exception:
            add(MED, "의존성", relpath, 0, "package.json 파싱 실패(손상·위장 가능)", "")
            return deps
        for hook in ("preinstall", "install", "postinstall", "prepare", "prepublish", "preuninstall", "postuninstall"):
            cmd = (pj.get("scripts") or {}).get(hook)
            if cmd:
                at_install = hook in ("preinstall", "install", "postinstall")
                add(HIGH if at_install else MED, "자동실행", relpath, 0,
                    f"npm '{hook}' 스크립트: " + ("설치만 해도 실행됨" if at_install else "git 주소로 설치·배포할 때 실행"), cmd[:200])
        for sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            for k, v in (pj.get(sec) or {}).items():
                v = str(v)
                deps.append({"ecosystem": "npm", "name": k, "version": v})
                if re.match(r"(git\+|git:|github:|https?:|file:|link:)", v) or "/" in v and not v.startswith("@"):
                    add(MED, "의존성", relpath, 0, f"레지스트리 밖에서 받는 패키지: {k}", v)
                elif v in ("*", "latest", "") or v.startswith(">"):
                    add(MED, "의존성", relpath, 0, f"버전 미고정: {k}", v)
    elif re.match(r"requirements.*\.txt$", name):
        for i, line in enumerate(text.splitlines(), 1):
            s = line.split("#", 1)[0].strip()
            if not s:
                continue
            if s.startswith(("--index-url", "-i ", "--extra-index-url", "--trusted-host", "-f ", "--find-links")):
                add(HIGH, "의존성", relpath, i, "패키지 저장소 바꿔치기(의존성 혼동 공격)", s)
                continue
            if re.match(r"(git\+|https?://|-e\s)", s):
                add(MED, "의존성", relpath, i, "PyPI 밖에서 받는 패키지", s)
                continue
            m = re.match(r"([A-Za-z0-9_.\-\[\]]+)\s*(==\s*([^\s;]+))?", s)
            if m:
                pkg = re.sub(r"\[.*\]", "", m.group(1))
                deps.append({"ecosystem": "PyPI", "name": pkg, "version": m.group(3) or ""})
                if not m.group(2):
                    add(LOW, "의존성", relpath, i, f"버전 미고정(==): {pkg}", s)
    elif name == "pyproject.toml":
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"(git\+|https?://).*(\.git|@)", line):
                add(MED, "의존성", relpath, i, "외부 주소 의존성", line.strip()[:200])
    for d in deps:
        t = typosquat(d["ecosystem"], d["name"])
        if t:
            add(HIGH, "의존성", relpath, 0, f"유명 패키지 '{t}'와 철자가 비슷한 이름(타이포스쿼팅 의심)", d["name"])
    return deps


def main():
    if len(sys.argv) < 4:
        print("사용법: python3 -I scan.py <대상폴더> <리포트.md> <결과.json>", file=sys.stderr)
        sys.exit(2)
    root = os.path.realpath(sys.argv[1])
    out_md, out_json = sys.argv[2], sys.argv[3]
    findings, inventory, deps = [], [], []

    def add(sev, cat, path, line, desc, snippet):
        findings.append({"심각도": sev, "분류": cat, "파일": path, "줄": line,
                         "설명": desc, "내용": (snippet or "")[:240]})

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for d in list(dirnames):
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                tgt = os.path.realpath(full)
                inside = tgt.startswith(root + os.sep)
                add(HIGH if not inside else MED, "심볼릭링크", rel(root, full), 0,
                    "폴더 밖을 가리키는 링크(복사 시 홈 폴더 노출·덮어쓰기)" if not inside else "폴더 링크", os.readlink(full))
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rp = rel(root, full)
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                tgt = os.path.realpath(full)
                inside = tgt.startswith(root + os.sep)
                add(HIGH if not inside else LOW, "심볼릭링크", rp, 0,
                    "폴더 밖을 가리키는 링크(~/.ssh 등 노출·덮어쓰기)" if not inside else "내부 링크", os.readlink(full))
                inventory.append({"파일": rp, "크기": 0, "종류": "링크", "sha256": ""})
                continue
            with open(full, "rb") as f:
                data = f.read()
            sha = hashlib.sha256(data).hexdigest()
            head = data[:4096]
            kind = magic_kind(head)
            binary = is_binary(fn, head)
            execbit = bool(st.st_mode & 0o111)
            inventory.append({"파일": rp, "크기": st.st_size, "종류": "바이너리" if binary else "텍스트",
                              "실행권한": execbit, "sha256": sha})

            norm = rp.replace(os.sep, "/")
            for key, (sev, desc) in AUTO_EXEC_FILES.items():
                if norm == key or norm.endswith("/" + key):
                    add(sev, "자동실행", rp, 0, desc, "")
            if fn.endswith(".pth"):
                add(HIGH if b"import" in data else MED, "자동실행", rp, 0, ".pth 파일: site-packages에 들어가면 파이썬 실행 때마다 자동 실행", data[:120].decode("utf-8", "replace"))
            if norm.startswith(".github/workflows/") or "/.github/workflows/" in norm:
                txt = data.decode("utf-8", "replace")
                if "pull_request_target" in txt or "workflow_run" in txt:
                    add(HIGH, "자동실행", rp, 0, "GitHub Actions pull_request_target/workflow_run: 포크 PR로 시크릿 탈취 가능(포크 후 Actions 켜기 전 확인)", "")
                else:
                    add(LOW, "자동실행", rp, 0, "GitHub Actions 워크플로우(포크에서 Actions 켜면 실행됨)", "")

            if binary:
                if kind in ("ELF 실행파일", "Mach-O 실행파일(macOS)", "Windows 실행파일"):
                    add(HIGH, "바이너리", rp, 0, f"{kind} 포함 — 소스 없이 내용 확인 불가", "")
                elif not re.search(r"\.(png|jpe?g|gif|webp|ico|svg|pdf|woff2?|ttf|otf|mp3|mp4|wav|mov)$", fn, re.I):
                    add(MED, "바이너리", rp, 0, f"바이너리/압축 파일({kind or '알 수 없음'})", "")
                else:
                    # 이미지 뒤에 붙인 페이로드 탐지(간이)
                    if re.search(rb"(#!/bin/|<\?php|import os|eval\(|powershell)", data):
                        add(MED, "바이너리", rp, 0, "이미지/미디어 안에 코드 문자열이 섞여 있음", "")
                continue
            if execbit and not kind:
                add(LOW, "실행권한", rp, 0, "실행 권한이 붙은 텍스트 파일", "")
            if st.st_size > TEXT_LIMIT:
                add(MED, "대용량", rp, 0, f"큰 텍스트 파일({st.st_size:,} bytes) — 내용 스캔 생략, 직접 확인", "")
                continue

            text = data.decode("utf-8", "replace")
            is_md = fn.lower().endswith((".md", ".mdx", ".txt"))

            # 숨은 유니코드
            for ln, k, cps in scan_hidden_unicode(text):
                sev = HIGH if ("태그" in k or "양방향" in k or "ANSI" in k) else MED
                add(sev, "숨은문자", rp, ln, k, " ".join(cps[:10]))
            payload = decode_tag_payload(text)
            if payload:
                add(HIGH, "숨은문자", rp, 0, "태그문자로 숨긴 텍스트 해독 결과", payload)

            lines = text.splitlines()
            for i, line in enumerate(lines, 1):
                if len(line) > 1000 and not fn.lower().endswith((".json", ".csv", ".svg", ".lock")):
                    add(MED, "난독화", rp, i, f"매우 긴 줄({len(line):,}자) — 압축/난독화 코드 의심", line[:120])
                # 압축된 긴 줄은 4,000자 조각(겹침 500자)으로 나눠 검사 — 정규식 폭주 방지
                segs = [line] if len(line) <= 4000 else [line[k:k + 4000] for k in range(0, len(line), 3500)]
                for cat, sev, rx, desc in LINE_RULES:
                    if cat == "원격지시" and sev == HIGH and "://" not in line:
                        continue  # 외부 주소 없는 "읽고 따르라"는 일반 문장
                    hit = next((m for sg in segs for m in [rx.search(sg)] if m), None)
                    if hit:
                        snip = line.strip() if len(line) <= 400 else line[max(0, hit.start() - 80):hit.end() + 80]
                        add(sev, cat, rp, i, desc, snip)
                for rx, desc in SECRET_RULES:
                    if rx.search(line):
                        add(MED, "시크릿", rp, i, f"{desc} — 남의 키 포함(저장소 관리 부실 신호)", rx.search(line).group(0)[:12] + "…")
                mt = mixed_script_tokens(line)
                if mt:
                    add(HIGH if not is_md else MED, "동형문자", rp, i, "라틴+키릴/그리스 문자가 섞인 단어(가짜 글자)", ", ".join(mt[:5]))

            if is_md:
                for m in re.finditer(r"<!--(.*?)-->", text, re.S):
                    body = m.group(1).strip()
                    if len(body) > 20:
                        ln = text[:m.start()].count("\n") + 1
                        add(MED, "숨은지시", rp, ln, "마크다운 HTML 주석(렌더링 화면엔 안 보이지만 AI는 읽음)", body[:200])
                for m in re.finditer(r"!\[([^\]]{80,})\]", text):
                    ln = text[:m.start()].count("\n") + 1
                    add(LOW, "숨은지시", rp, ln, "이미지 대체텍스트가 길다(지시 숨김 확인)", m.group(1)[:200])

            # 스킬/에이전트/커맨드 프론트매터
            if fn in ("SKILL.md",) or "/agents/" in "/" + norm or "/commands/" in "/" + norm:
                fm = parse_frontmatter(text)
                if fm is not None:
                    if re.search(r"(?m)^\s*hooks\s*:", fm):
                        add(HIGH, "권한범위", rp, 0, "프론트매터에 hooks 정의 — 스킬 사용 중 자동 실행", "")
                    at = re.search(r"(?ms)^allowed-tools\s*:(.*?)(^\S|\Z)", fm)
                    if at:
                        v = at.group(1)
                        if re.search(r"\bBash\b(?!\()", v) or "Bash(*)" in v or re.search(r"Bash\([^)]*\*\s*\)", v):
                            add(MED, "권한범위", rp, 0, "allowed-tools에 제한 없는 Bash — 확인 없이 셸 실행 가능", v.strip()[:200])
                        if re.search(r"\b(Write|Edit)\b", v):
                            add(LOW, "권한범위", rp, 0, "allowed-tools에 파일 쓰기 포함", v.strip()[:200])
                    if re.search(r"(?m)^\s*model\s*:", fm):
                        add(LOW, "권한범위", rp, 0, "모델 지정(비용 영향 확인)", "")

            # 스킬·커맨드 본문의 인라인 셸(!`명령`): Claude가 읽기도 전에, 불러오는 순간 실행됨
            if fn == "SKILL.md" or "/commands/" in "/" + norm or "/agents/" in "/" + norm:
                for m in re.finditer(r"(?m)(^|[\s(])!`([^`\n]+)`", text):
                    ln = text[:m.start()].count("\n") + 1
                    add(HIGH, "자동실행", rp, ln, "인라인 셸 !`명령` — 스킬을 불러오는 순간 확인 없이 실행", m.group(2)[:200])

            # MCP 서버 설정: 버전 미고정 패키지(나중에 바꿔치기)·원격 서버·시크릿 전달
            if fn in (".mcp.json", "plugin.json", "marketplace.json", "claude_desktop_config.json") or fn.endswith(".mcp.json"):
                try:
                    cfg = json.loads(text)
                except Exception:
                    cfg = None
                servers = {}
                if isinstance(cfg, dict):
                    servers.update(cfg.get("mcpServers") or {})
                    for pl in cfg.get("plugins") or []:
                        if isinstance(pl, dict):
                            servers.update(pl.get("mcpServers") or {})
                            src = pl.get("source")
                            if isinstance(src, dict) and src.get("source") in ("github", "git", "url") and not (src.get("sha") or src.get("ref")):
                                add(MED, "MCP", rp, 0, f"마켓플레이스 플러그인 '{pl.get('name')}'이 다른 저장소를 버전 고정 없이 가져옴", json.dumps(src)[:200])
                for name, s in servers.items():
                    if not isinstance(s, dict):
                        continue
                    cmd = " ".join([str(s.get("command", ""))] + [str(a) for a in s.get("args") or []])
                    if re.search(r"\b(npx|bunx|pnpm\s+dlx)\b", cmd):
                        pkgs = [a for a in (s.get("args") or []) if not str(a).startswith("-")]
                        if pkgs and not re.search(r".@\d", str(pkgs[0])):
                            add(MED, "MCP", rp, 0, f"MCP '{name}': npm 패키지 버전 미고정 — 실행할 때마다 최신을 받아 바꿔치기 위험", cmd[:200])
                        if "@latest" in cmd:
                            add(MED, "MCP", rp, 0, f"MCP '{name}': @latest 사용", cmd[:200])
                    if re.search(r"\buvx\b|\bpipx\s+run\b", cmd) and "==" not in cmd and "@" not in cmd:
                        add(MED, "MCP", rp, 0, f"MCP '{name}': 파이썬 패키지 버전 미고정", cmd[:200])
                    if re.search(r"(curl|wget)[^\n]*\|", cmd) or re.search(r"\b(bash|sh|zsh)\s+-c\b", cmd):
                        add(HIGH, "MCP", rp, 0, f"MCP '{name}': 셸로 임의 명령 실행", cmd[:200])
                    if s.get("url") or s.get("type") in ("http", "sse"):
                        add(MED, "MCP", rp, 0, f"MCP '{name}': 원격 서버 — 대화 내용·도구 결과가 외부로 전송됨", str(s.get("url"))[:200])
                    env = s.get("env") or {}
                    if any(re.search(r"(KEY|TOKEN|SECRET|PASS)", k, re.I) for k in env):
                        add(LOW, "MCP", rp, 0, f"MCP '{name}': 키·토큰을 환경변수로 넘김(값은 이 파일에 직접 쓰지 말 것)", ", ".join(env)[:200])

            deps += check_dependencies(root, rp, text, add)

    for f in findings:
        if re.search(r"(^|/)(node_modules|vendor|site-packages|\.venv)/", f["파일"]) and f["분류"] not in ("바이너리", "심볼릭링크"):
            f["심각도"] = {HIGH: MED, MED: LOW, LOW: LOW}[f["심각도"]]
            f["설명"] = "[번들 의존성] " + f["설명"]
    findings.sort(key=lambda f: (SEV_ORDER[f["심각도"]], f["파일"], f["줄"]))
    counts = {s: sum(1 for f in findings if f["심각도"] == s) for s in (HIGH, MED, LOW)}
    result = {"대상": root, "파일수": len(inventory), "건수": counts,
              "발견": findings, "의존성": deps, "파일목록": inventory}
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=1)

    md = [f"# 정적 스캔 결과\n", f"- 대상: `{root}`", f"- 파일 {len(inventory)}개 · 위험 {counts[HIGH]} · 주의 {counts[MED]} · 참고 {counts[LOW]}\n"]
    if findings:
        md.append("| 심각도 | 분류 | 위치 | 설명 | 내용 |\n|---|---|---|---|---|")
        for x in findings:
            loc = f"{x['파일']}:{x['줄']}" if x["줄"] else x["파일"]
            snip = x["내용"].replace("|", "\\|").replace("\n", " ")
            md.append(f"| {x['심각도']} | {x['분류']} | `{loc}` | {x['설명']} | `{snip}` |")
    if deps:
        md.append(f"\n## 의존성 {len(deps)}개 (OSV 취약점 조회 대상)\n")
        for d in deps:
            md.append(f"- {d['ecosystem']} `{d['name']}` {d['version']}")
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")
    print(f"파일 {len(inventory)}개 · 위험 {counts[HIGH]} · 주의 {counts[MED]} · 참고 {counts[LOW]}")
    print(f"리포트: {out_md}\nJSON: {out_json}")


if __name__ == "__main__":
    main()
