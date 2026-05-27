package cmd

import (
	"bufio"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

var inputReader *bufio.Reader

func init() {
	inputReader = bufio.NewReader(os.Stdin)
}

func readPassword() ([]byte, error) {
	if !term.IsTerminal(int(syscall.Stdin)) {
		pass, err := inputReader.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}
		// remove \r\n or \n
		pass = strings.TrimRight(pass, "\r\n")
		return []byte(pass), nil
	}
	return term.ReadPassword(int(syscall.Stdin))
}
