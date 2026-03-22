package main

import (
	"fmt"
	"os"

	"github.com/HarborGuard/harborguard-sensor/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
