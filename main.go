// spf-checker は、ドメインの SPF レコードを表示し、指定した IP アドレスが
// そのドメインの送信元として認可されているかを RFC 7208 に沿って判定する
// コマンドラインツールである。
package main

import (
	"context"
	"flag"
	"os"

	"github.com/google/subcommands"

	"spf-checker/internal/cmd"
)

// main はサブコマンドを登録し、選択されたサブコマンドの終了ステータスで
// プロセスを終了する。終了ステータスの意味は check サブコマンドの
// Usage を参照。
func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(&cmd.ListCmd{}, "")
	subcommands.Register(&cmd.CheckCmd{}, "")
	flag.Parse()

	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
