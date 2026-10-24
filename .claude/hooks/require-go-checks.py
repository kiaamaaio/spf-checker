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
import time

# git のサブコマンドが commit のときだけ検査する。
# git -C path commit のようなグローバルオプション付きも拾い、
# git log --grep=commit のような読み取り専用コマンドは拾わない。
# オプション値は -c user.name="A B" のような引用符付きの空白も 1 トークンとして扱い、
# commit の直後が ; ) & | などで終わる場合も拾う。
_TOKEN = r"""(?:[^\s"']|"[^"]*"|'[^']*')+"""
GIT_COMMIT_RE = re.compile(
    r"(?:^|[^\w.-])git(?:\s+-%s(?:\s+(?!-)%s)?)*\s+commit(?![\w-])" % (_TOKEN, _TOKEN))

# 実行順に並べたチェック。静的解析を先に通してからテストを走らせる。
CHECKS = [["vet", "./..."], ["test", "./..."]]
MAX_OUTPUT = 3000
# フック自体のタイムアウト (settings.json の 300 秒) より前に打ち切り、理由を返せるようにする。
CHECK_BUDGET = 280


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

    # シェルがサブディレクトリにいても ./... がモジュール全体を指すよう、プロジェクトルートを優先する。
    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or os.getcwd()
    if not os.path.isdir(cwd):
        cwd = os.getcwd()

    go = shutil.which("go")
    if go is None:
        deny("go コマンドが見つからず go vet / go test を実行できませんでした。"
             "未確認のままコミットしないため中止しました。")

    deadline = time.monotonic() + CHECK_BUDGET
    for args in CHECKS:
        label = "go " + " ".join(args)
        try:
            proc = subprocess.run([go] + args, cwd=cwd, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True,
                                  timeout=max(1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            deny("%s が %d 秒以内に終わらなかったためコミットを中止しました。"
                 "ハングしているテストが無いか確認してください。" % (label, CHECK_BUDGET))
        if proc.returncode != 0:
            # 成功したパッケージの ok / ? 行を除き、失敗の詳細が切り捨てられにくくする。
            lines = [l for l in proc.stdout.splitlines() if not l.startswith(("ok  ", "?   "))]
            output = "\n".join(lines)[-MAX_OUTPUT:]
            deny("%s が失敗したためコミットを中止しました。"
                 "指摘を修正し、パスしてから再度コミットしてください。\n\n%s" % (label, output))

    json.dump({"systemMessage": "go vet ./... と go test ./... が成功。コミットを続行します。",
               "suppressOutput": True}, sys.stdout)


if __name__ == "__main__":
    main()
