# 외부 스킬 설치 전 보안 점검 (skill-security-vetting)

깃허브에서 받은 Claude 스킬·플러그인·MCP 서버를 **설치하기 전에**, 개발자들이 남의 저장소를 포크·클론할 때 보는 보안 항목을 **실행 없이 읽기만 해서** 점검하는 Claude Code 스킬입니다. 결과를 🔴 설치 비권장 / 🟡 조건부 / 🟢 통과로 보고하고, 승인한 경우에만 **점검한 바로 그 사본**을 설치합니다.

설치 뒤에도 감시 훅 두 겹이 지킵니다.
- **작업 중 (실시간)**: 확실한 악성(스킬 폴더에 외부 코드 바로 받기, 다운로드 후 바로 실행, SSH 키·키체인·쿠키 접근, 웹훅 전송, 리버스 셸 등)만 자동 차단하고 나머지는 기록만 해서 오토 모드를 끊지 않아요. 승인창은 감시 기준선 갱신 때만 떠요
- **세션 시작 때**: 스킬·플러그인·훅·MCP 설정이 지난번 승인 상태와 달라졌으면 알림 + 자동 스캔

## 이렇게 써요
- "이 스킬 설치해줘 https://github.com/…"
- "이 깃허브 스킬 안전한지 봐줘", "이 MCP 서버 깔아도 돼?"

## 설치
요구 사항: macOS 또는 Linux, `python3` 3.8+(표준 라이브러리만), `git`, `gh`(GitHub CLI, 출처 조회용). 유료 도구·API는 쓰지 않습니다.

1. 임시 폴더에 받아 내용을 확인한 뒤 `~/.claude/skills/skill-security-vetting/`로 복사합니다. (이 스킬의 감시 훅은 스킬 폴더에 바로 `git clone`하는 것을 막기 때문에, 업데이트할 때도 같은 방식으로 합니다)
   ```bash
   git clone https://github.com/sunny1234303-cmd/aha-skill-skill-security-vetting.git /tmp/skill-security-vetting
   mkdir -p ~/.claude/skills/skill-security-vetting
   cp -R /tmp/skill-security-vetting/SKILL.md /tmp/skill-security-vetting/hooks /tmp/skill-security-vetting/scripts /tmp/skill-security-vetting/installed-log.md ~/.claude/skills/skill-security-vetting/
   ```
2. 감시 훅 등록과 기준선 만들기는 `SKILL.md`의 **"처음 설치할 때 (1회)"** 절을 따라 하세요. (`~/.claude/settings.json`의 `hooks`에 두 항목 추가 → `guard.py baseline-init` 실행)

훅 없이 점검 절차만 쓰고 싶으면 2번을 건너뛰어도 됩니다.

## 들어 있는 것
| 파일 | 하는 일 |
|---|---|
| `SKILL.md` | 6단계 점검 절차(출처 → 격리 다운로드 → 정적 스캔 → 직접 읽기 → 보고 → 승인 후 설치)와 판정 기준 |
| `scripts/scan.py` | 정적 스캔 — 원격 즉시 실행, 유출 경로, 지속성, 프롬프트 인젝션, 숨은 유니코드, 자동 실행 파일, 의존성 등 |
| `scripts/install_verified.py` | 점검 때 기록한 파일 해시와 같은 사본만 설치(덮어쓰기 안 함, 실행 권한 제거) |
| `hooks/guard.py` | 실시간 감시(PreToolUse)·세션 시작 무결성 검사(SessionStart)·`baseline-init`·`accept`·`status` |
| `installed-log.md` | 설치 기록(빈 양식) |

`state/` 폴더(기준선·대기 결과·감시 기록)는 각자 컴퓨터에서 처음 실행할 때 새로 생기는 개인 기록이라 저장소에 넣지 않습니다.

## 알아 둘 한계
- 정적 점검이라 실행해야만 드러나는 동작은 못 볼 수 있어요. 그래서 4단계에서 Claude가 파일을 직접 끝까지 읽습니다.
- 파이썬 스크립트 *안에서* 쓰는 파일처럼 명령 문자열에 드러나지 않는 쓰기는 실시간으로 못 잡고, 다음 세션 시작 때 잡습니다.
- 훅이 오류로 멈추면 작업을 막지 않고 통과시킵니다. Claude 밖 터미널에서 한 일은 다음 세션 시작 때 감지합니다.
- 이 스킬 자신을 스캔하면 패턴 목록 때문에 위험 항목이 많이 나오는 게 정상입니다.
