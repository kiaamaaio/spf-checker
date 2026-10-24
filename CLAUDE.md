# spf-checker

## コミット前の必須チェック

`git commit` する前に必ず `go vet ./...` と `go test ./...` を実行し、
どちらも問題無い事を確認する。失敗している場合はコミットせず、先に直す。

このルールは `.claude/settings.json` の PreToolUse フック
(`.claude/hooks/require-go-checks.py`) で強制されており、vet の指摘やテストの
失敗があると Claude の `git commit` 自体がブロックされる。
