package main

import (
	"context"
	"flag"
	"github.com/google/subcommands"
	"os"
	"spf-checker/internal/cmd"
)

func main() {
	subcommands.Register(&cmd.ListCmd{}, "")
	subcommands.Register(&cmd.CheckCmd{}, "")
	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
