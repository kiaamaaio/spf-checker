#!/usr/bin/env python3
"""PreToolUse(Bash) フック。

git commit を実行する直前に go vet ./... と go test ./... を走らせ、
どちらかが失敗した場合はコミットをブロックする。
標準入力でフック入力の JSON を受け取り、ブロック時は permissionDecision: deny を返す。
"""

import json
import os
import re
import shutil
import subprocess
import sys

# git のサブコマンドが commit のときだけ検査する。
# git -C path commit のようなグローバルオプション付きも拾い、
# git log --grep=commit のような読み取り専用コマンドは拾わない。
GIT_COMMIT_RE = re.compile(r"(?:^|[^\w.-])git(?:\s+-\S+(?:\s+[^-\s]\S*)?)*\s+commit(?:\s|$)")

# 実行順に並べたチェック。静的解析を先に通してからテストを走らせる。
CHECKS = [["vet", "./..."], ["test", "./..."]]
MAX_OUTPUT = 3000


def deny(reason):
    """コミットを拒否し、理由を Claude に返す。"""
    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        },
        sys.stdout,
    )
    sys.exit(0)


def main():
    try:
        payload = json.loads(sys.stdin.read())
    except ValueError:
        deny("フック入力の解析に失敗し go vet / go test を実行できませんでした。"
             "未確認のままコミットしないため中止しました。")

    command = payload.get("tool_input", {}).get("command") or ""
    if not GIT_COMMIT_RE.search(command):
        return

    cwd = payload.get("cwd") or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    if not os.path.isdir(cwd):
        cwd = os.getcwd()

    go = shutil.which("go")
    if go is None:
        deny("go コマンドが見つからず go vet / go test を実行できませんでした。"
             "未確認のままコミットしないため中止しました。")

    for args in CHECKS:
        label = "go " + " ".join(args)
        proc = subprocess.run([go] + args, cwd=cwd, capture_output=True, text=True)
        if proc.returncode != 0:
            output = (proc.stdout + proc.stderr)[-MAX_OUTPUT:]
            deny("%s が失敗したためコミットを中止しました。"
                 "指摘を修正し、パスしてから再度コミットしてください。\n\n%s" % (label, output))

    json.dump({"systemMessage": "go vet ./... と go test ./... が成功。コミットを続行します。",
               "suppressOutput": True}, sys.stdout)


if __name__ == "__main__":
    main()
