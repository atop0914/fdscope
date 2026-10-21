// Command fdscope audits file descriptor usage of a Linux process.
//
// It answers a question /proc and lsof cannot answer on their own: *why* is the
// descriptor count growing, and which resource is responsible. Output is a
// human table by default and JSON with --json.
package main

import (
	"fmt"
	"os"

	"github.com/atop0914/fdscope/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		// Exit codes are part of the contract because CI branches on them:
		//   0 success, 1 usage or runtime error, 2 check found a leak.
		if code := cli.ExitCode(err); code != 0 {
			fmt.Fprintln(os.Stderr, "fdscope:", err)
			os.Exit(code)
		}
		fmt.Fprintln(os.Stderr, "fdscope:", err)
		os.Exit(1)
	}
}
