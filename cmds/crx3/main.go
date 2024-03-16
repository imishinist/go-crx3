package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
)

func main() {
	commands := map[string]command{
		"pack": packCmd(),
	}

	fs := flag.NewFlagSet("crx3", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: crx3 <command> [command flags]")
		fmt.Fprintf(fs.Output(), "\nglobal flags: \n")
		fs.PrintDefaults()

		names := make([]string, 0, len(commands))
		for name := range commands {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if cmd := commands[name]; cmd.fs != nil {
				fmt.Fprintf(fs.Output(), "\n%s command: \n", name)
				cmd.fs.SetOutput(fs.Output())
				cmd.fs.PrintDefaults()
			}
		}
	}
	fs.Parse(os.Args[1:])

	args := fs.Args()
	if len(args) == 0 {
		fs.Usage()
		os.Exit(1)
	}

	cmd, ok := commands[args[0]]
	if !ok {
		log.Fatalf("Unknown command: %s", args[0])
	}
	if err := cmd.fn(args[1:]); err != nil {
		log.Fatal(err)
	}
}

type command struct {
	fs *flag.FlagSet
	fn func(args []string) error
}
