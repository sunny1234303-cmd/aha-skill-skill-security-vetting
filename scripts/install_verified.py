#!/usr/bin/env python3
"""
점검을 통과한 '바로 그 사본'만 설치한다 (다시 다운로드하지 않음 → 점검 후 바꿔치기 방지).

python3 -I install_verified.py <점검한폴더> <scan결과.json> <설치위치>

- scan.py가 기록한 sha256과 지금 파일이 하나라도 다르면 중단
- 심볼릭링크·.git은 복사하지 않음
- 설치 위치가 이미 있으면 덮어쓰지 않고 중단(기존 스킬 보호)
- 실행 권한은 모두 제거하고 복사
"""
import hashlib
import json
import os
import shutil
import sys


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(2)
    src, scan_json, dest = (os.path.realpath(p) for p in sys.argv[1:])
    with open(scan_json, encoding="utf-8") as f:
        scan = json.load(f)
    if os.path.realpath(scan["대상"]) != src:
        sys.exit(f"중단: 점검한 폴더({scan['대상']})와 설치하려는 폴더({src})가 다릅니다.")
    if os.path.exists(dest):
        sys.exit(f"중단: 설치 위치가 이미 있습니다 → {dest} (덮어쓰기는 사용자 승인 후 직접 처리)")

    files = [x for x in scan["파일목록"] if x.get("종류") != "링크"]
    for x in files:
        p = os.path.join(src, x["파일"])
        if os.path.islink(p) or not os.path.isfile(p):
            sys.exit(f"중단: 점검 후 파일 상태가 바뀜 → {x['파일']}")
        with open(p, "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() != x["sha256"]:
                sys.exit(f"중단: 점검 후 내용이 바뀜 → {x['파일']}")

    # 점검 때 없던 파일이 생겼는지도 확인
    seen = {x["파일"] for x in scan["파일목록"]}
    for dp, dns, fns in os.walk(src):
        dns[:] = [d for d in dns if d != ".git"]
        for fn in fns:
            r = os.path.relpath(os.path.join(dp, fn), src)
            if r not in seen:
                sys.exit(f"중단: 점검 후 새 파일이 생김 → {r}")

    os.makedirs(dest)
    for x in files:
        s = os.path.join(src, x["파일"])
        d = os.path.join(dest, x["파일"])
        os.makedirs(os.path.dirname(d), exist_ok=True)
        shutil.copyfile(s, d)  # 권한·속성은 복사하지 않음
        os.chmod(d, 0o644)
    print(f"설치 완료: {dest} (파일 {len(files)}개, 해시 일치, 실행권한 제거)")
    # 자동 감시 기준선에 '점검 통과본'으로 등록 (다음 세션에서 경고하지 않도록)
    import subprocess
    guard = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks", "guard.py")
    skills_root = os.path.realpath(os.path.expanduser("~/.claude/skills"))
    if os.path.dirname(dest) == skills_root and os.path.exists(guard):
        r = subprocess.run([sys.executable, "-I", guard, "accept", "skill:" + os.path.basename(dest)], capture_output=True, text=True)
        print(r.stdout.strip() or r.stderr.strip())


if __name__ == "__main__":
    main()
