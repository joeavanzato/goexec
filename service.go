package main

// TODO - Delete Service if no name specified
// TODO - Deploy minimal binary for command-execution to avoid issues with Windows Service Parsing

import (
	"bufio"
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// Windows API constants for service control
const (
	// Access rights for Service Control Manager
	SC_MANAGER_CONNECT            = 0x0001
	SC_MANAGER_CREATE_SERVICE     = 0x0002
	SC_MANAGER_ENUMERATE_SERVICE  = 0x0004
	SC_MANAGER_LOCK               = 0x0008
	SC_MANAGER_QUERY_LOCK_STATUS  = 0x0010
	SC_MANAGER_MODIFY_BOOT_CONFIG = 0x0020
	SC_MANAGER_ALL_ACCESS         = 0xF003F

	// Access rights for service
	SERVICE_QUERY_CONFIG         = 0x0001
	SERVICE_CHANGE_CONFIG        = 0x0002
	SERVICE_QUERY_STATUS         = 0x0004
	SERVICE_ENUMERATE_DEPENDENTS = 0x0008
	SERVICE_START                = 0x0010
	SERVICE_STOP                 = 0x0020
	SERVICE_PAUSE_CONTINUE       = 0x0040
	SERVICE_INTERROGATE          = 0x0080
	SERVICE_USER_DEFINED_CONTROL = 0x0100
	SERVICE_ALL_ACCESS           = 0xF01FF

	SERVICE_NO_CHANGE = 0xFFFFFFFF

	// Service types
	SERVICE_KERNEL_DRIVER       = 0x00000001
	SERVICE_FILE_SYSTEM_DRIVER  = 0x00000002
	SERVICE_ADAPTER             = 0x00000004
	SERVICE_RECOGNIZER_DRIVER   = 0x00000008
	SERVICE_DRIVER              = SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_RECOGNIZER_DRIVER
	SERVICE_WIN32_OWN_PROCESS   = 0x00000010
	SERVICE_WIN32_SHARE_PROCESS = 0x00000020
	SERVICE_WIN32               = SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS
	SERVICE_INTERACTIVE_PROCESS = 0x00000100
	SERVICE_TYPE_ALL            = SERVICE_WIN32 | SERVICE_ADAPTER | SERVICE_DRIVER | SERVICE_INTERACTIVE_PROCESS

	// Service start types
	SERVICE_BOOT_START   = 0x00000000
	SERVICE_SYSTEM_START = 0x00000001
	SERVICE_AUTO_START   = 0x00000002
	SERVICE_DEMAND_START = 0x00000003
	SERVICE_DISABLED     = 0x00000004

	// Service error control
	SERVICE_ERROR_IGNORE   = 0x00000000
	SERVICE_ERROR_NORMAL   = 0x00000001
	SERVICE_ERROR_SEVERE   = 0x00000002
	SERVICE_ERROR_CRITICAL = 0x00000003

	// Service control codes
	SERVICE_CONTROL_STOP                  = 0x00000001
	SERVICE_CONTROL_PAUSE                 = 0x00000002
	SERVICE_CONTROL_CONTINUE              = 0x00000003
	SERVICE_CONTROL_INTERROGATE           = 0x00000004
	SERVICE_CONTROL_SHUTDOWN              = 0x00000005
	SERVICE_CONTROL_PARAMCHANGE           = 0x00000006
	SERVICE_CONTROL_NETBINDADD            = 0x00000007
	SERVICE_CONTROL_NETBINDREMOVE         = 0x00000008
	SERVICE_CONTROL_NETBINDENABLE         = 0x00000009
	SERVICE_CONTROL_NETBINDDISABLE        = 0x0000000A
	SERVICE_CONTROL_DEVICEEVENT           = 0x0000000B
	SERVICE_CONTROL_HARDWAREPROFILECHANGE = 0x0000000C
	SERVICE_CONTROL_POWEREVENT            = 0x0000000D
	SERVICE_CONTROL_SESSIONCHANGE         = 0x0000000E

	// Service state
	SERVICE_STOPPED          = 0x00000001
	SERVICE_START_PENDING    = 0x00000002
	SERVICE_STOP_PENDING     = 0x00000003
	SERVICE_RUNNING          = 0x00000004
	SERVICE_CONTINUE_PENDING = 0x00000005
	SERVICE_PAUSE_PENDING    = 0x00000006
	SERVICE_PAUSED           = 0x00000007

	// Service config information
	SERVICE_CONFIG_DESCRIPTION     = 1
	SERVICE_CONFIG_FAILURE_ACTIONS = 2
)

// SERVICE_STATUS represents the status of a service
type SERVICE_STATUS struct {
	DwServiceType             uint32
	DwCurrentState            uint32
	DwControlsAccepted        uint32
	DwWin32ExitCode           uint32
	DwServiceSpecificExitCode uint32
	DwCheckPoint              uint32
	DwWaitHint                uint32
}

// SERVICE_DESCRIPTION structure used for setting service description
type SERVICE_DESCRIPTION struct {
	LpDescription *uint16
}

// ServiceStateToString converts a service state code to a human-readable string
func ServiceStateToString(state uint32) string {
	switch state {
	case SERVICE_STOPPED:
		return "Stopped"
	case SERVICE_START_PENDING:
		return "Start Pending"
	case SERVICE_STOP_PENDING:
		return "Stop Pending"
	case SERVICE_RUNNING:
		return "Running"
	case SERVICE_CONTINUE_PENDING:
		return "Continue Pending"
	case SERVICE_PAUSE_PENDING:
		return "Pause Pending"
	case SERVICE_PAUSED:
		return "Paused"
	default:
		return fmt.Sprintf("Unknown (%d)", state)
	}
}

// Called during setup to prepare a service for use
func CreateRemoteService(machineName, serviceName, displayName, description, binPath, username, password, domain string, runas bool) error {
	// Open Service Control Manager on remote machine
	token, err := logonUser(username, domain, password)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(token)

	if err = impersonateUser(token); err != nil {
		return err
	}
	defer revertToSelf()

	// Connect to the Service Control Manager on the specified machine
	scmHandle, _, err := procOpenSCManagerW.Call(
		uintptr(unsafe.Pointer(UTF16PtrFromString(machineName))),
		uintptr(unsafe.Pointer(UTF16PtrFromString("ServicesActive"))),
		uintptr(SC_MANAGER_ALL_ACCESS),
	)

	if scmHandle == 0 {
		return fmt.Errorf("failed to open Service Control Manager: %v (Error code: %d)", err, syscall.GetLastError())
	}
	defer procCloseServiceHandle.Call(scmHandle)

	log.Printf("Successfully opened Service Control Manager on %s\n", machineName)

	// Check if service already exists and try to open it
	serviceHandle, _, _ := procOpenServiceW.Call(
		scmHandle,
		uintptr(unsafe.Pointer(UTF16PtrFromString(serviceName))),
		uintptr(SERVICE_ALL_ACCESS),
	)

	if serviceHandle != 0 {
		// Service exists, attempt to stop it first if it's running
		// Then we just return since we already
		var serviceStatus SERVICE_STATUS
		procQueryServiceStatus.Call(serviceHandle, uintptr(unsafe.Pointer(&serviceStatus)))

		if serviceStatus.DwCurrentState != SERVICE_STOPPED {
			log.Printf("Service '%s' is running, attempting to stop it\n", serviceName)
			success, _, stopErr := procControlService.Call(
				serviceHandle,
				uintptr(SERVICE_CONTROL_STOP),
				uintptr(unsafe.Pointer(&serviceStatus)),
			)

			if success == 0 {
				log.Printf("Warning: Failed to stop service: %v\n", stopErr)
			} else {
				// Wait for service to stop (with timeout)
				stopTimeout := time.Now().Add(30 * time.Second)
				for serviceStatus.DwCurrentState != SERVICE_STOPPED {
					if time.Now().After(stopTimeout) {
						log.Printf("Warning: Timeout waiting for service to stop\n")
						break
					}

					time.Sleep(500 * time.Millisecond)
					procQueryServiceStatus.Call(serviceHandle, uintptr(unsafe.Pointer(&serviceStatus)))
				}
			}
		}
		return nil
	}
	// Create the new service
	lpServiceStartName := uintptr(0)
	lpPassword := uintptr(0)
	if runas {
		lpServiceStartName = uintptr(unsafe.Pointer(UTF16PtrFromString(fmt.Sprintf("%s\\%s", domain, username))))
		lpPassword = uintptr(unsafe.Pointer(UTF16PtrFromString(password)))
	}

	serviceHandle, _, err = procCreateServiceW.Call(
		scmHandle,
		uintptr(unsafe.Pointer(UTF16PtrFromString(serviceName))),
		uintptr(unsafe.Pointer(UTF16PtrFromString(displayName))),
		uintptr(SERVICE_ALL_ACCESS),
		uintptr(SERVICE_WIN32_OWN_PROCESS),
		uintptr(SERVICE_DEMAND_START),
		uintptr(SERVICE_ERROR_NORMAL),
		uintptr(unsafe.Pointer(UTF16PtrFromString(binPath))),
		0,                  // lpLoadOrderGroup
		0,                  // lpdwTagId
		0,                  // lpDependencies
		lpServiceStartName, // lpServiceStartName (account name)
		lpPassword,         // lpPassword
	)

	if serviceHandle == 0 {
		return fmt.Errorf("failed to create service: %v (Error code: %d)", err, syscall.GetLastError())
	}
	defer procCloseServiceHandle.Call(serviceHandle)

	// Set service description if provided
	if description != "" {
		// Create SERVICE_DESCRIPTION struct with description
		descPtr := UTF16PtrFromString(description)
		svcDesc := SERVICE_DESCRIPTION{
			LpDescription: descPtr,
		}

		// Call ChangeServiceConfig2W to set the description
		success, _, err := procChangeServiceConfig2W.Call(
			serviceHandle,
			uintptr(SERVICE_CONFIG_DESCRIPTION),
			uintptr(unsafe.Pointer(&svcDesc)),
		)

		// Non-fatal error
		if success == 0 {
			fmt.Printf("Warning: Failed to set service description: %v (Error code: %d)\n", err, syscall.GetLastError())
		}
	}
	return nil
}

func executeRemoteService(target string, cmd string, user string, password string, domain string, servicename string) error {
	// Open Service Control Manager on remote machine
	token, err := logonUser(user, domain, password)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(token)

	if err = impersonateUser(token); err != nil {
		return err
	}
	defer revertToSelf()

	scmHandle, _, err := procOpenSCManagerW.Call(
		uintptr(unsafe.Pointer(UTF16PtrFromString(target))),
		uintptr(unsafe.Pointer(UTF16PtrFromString("ServicesActive"))),
		uintptr(SC_MANAGER_ALL_ACCESS),
	)

	if scmHandle == 0 {
		return fmt.Errorf("Failed to open Service Control Manager: %v (Error code: %d)\n", err, syscall.GetLastError())
	}
	defer procCloseServiceHandle.Call(scmHandle)

	serviceHandle, _, err := procOpenServiceW.Call(
		scmHandle,
		uintptr(unsafe.Pointer(UTF16PtrFromString(servicename))),
		uintptr(SERVICE_ALL_ACCESS),
	)

	if serviceHandle == 0 {
		return fmt.Errorf("Failed to open service: %v (Error code: %d)\n", err, syscall.GetLastError())
	}
	defer procCloseServiceHandle.Call(serviceHandle)

	ret, _, err := procChangeServiceConfigW.Call(
		serviceHandle,
		SERVICE_NO_CHANGE,    // dwServiceType
		SERVICE_DEMAND_START, // dwStartType
		SERVICE_NO_CHANGE,    // dwErrorControl
		uintptr(unsafe.Pointer(UTF16PtrFromString(cmd))), // lpBinaryPathName
		0, 0, 0, 0, 0, 0,
	)
	if ret == 0 {
		return fmt.Errorf("ChangeServiceConfigW failed: %v", err)
	}

	err = windows.StartService(windows.Handle(serviceHandle), 0, nil)
	if err != nil {
		return err
	}
	/*	success, _, err := procStartServiceW.Call(serviceHandle, 0, 0)
		if success == 0 {
			fmt.Println(err.Error())
			return fmt.Errorf("Failed to start service: %s", err)
		}*/
	return nil

}

func checkServiceState(target string, user string, password string, domain string, servicename string) (string, error) {
	// Open Service Control Manager on remote machine
	token, err := logonUser(user, domain, password)
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(token)

	if err = impersonateUser(token); err != nil {
		return "", err
	}
	defer revertToSelf()

	scmHandle, _, err := procOpenSCManagerW.Call(
		uintptr(unsafe.Pointer(UTF16PtrFromString(target))),
		uintptr(unsafe.Pointer(UTF16PtrFromString("ServicesActive"))),
		uintptr(SC_MANAGER_ALL_ACCESS),
	)

	if scmHandle == 0 {
		return "", fmt.Errorf("Failed to open Service Control Manager: %v (Error code: %d)\n", err, syscall.GetLastError())

	}
	defer procCloseServiceHandle.Call(scmHandle)

	serviceHandle, _, err := procOpenServiceW.Call(
		scmHandle,
		uintptr(unsafe.Pointer(UTF16PtrFromString(servicename))),
		uintptr(SERVICE_ALL_ACCESS),
	)

	if serviceHandle == 0 {
		return "", fmt.Errorf("Failed to open service: %v (Error code: %d)\n", err, syscall.GetLastError())
	}
	defer procCloseServiceHandle.Call(serviceHandle)

	var serviceStatus SERVICE_STATUS
	procQueryServiceStatus.Call(serviceHandle, uintptr(unsafe.Pointer(&serviceStatus)))

	return ServiceStateToString(serviceStatus.DwCurrentState), nil
}

func handleServiceSession(target string, batch bool, username string, password string, domain string, servicename string, description string, runas bool) {
	if servicename == "" {
		servicename = getRandomString(12)
	}
	err := CreateRemoteService(target, servicename, servicename, "Bluetooth controller for XAIE", "cmd.exe /c cmd.exe", username, password, domain, runas)
	if err != nil {
		fmt.Printf("Failed to create service: %v\n", err)
		return
	}
	fmt.Printf("Successfully created service %s at %s \n", servicename, target)

	// Now we know a service with name=servicename should exist on the target
	// Each time we provide a command, we will modify the binary of the service, start it and wait for it to finish
	// Then we can read the output file via SMB
	settings := &Settings{
		User:        fmt.Sprintf("%s\\%s", domain, username),
		Password:    password,
		TargetShare: "ADMIN$",
		Target:      target,
	}

	if !EstablishConnection(settings, "C$", true) {
		fmt.Printf("failed to establish connection to C$ share on %s", settings.Target)
		return
	}
	defer EstablishConnection(settings, "C$", false)
	log.Printf("Successfully connected to C$ share on %s\n", target)

	for true {
		fmt.Printf("service@%s: ", target)
		var command string
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			command = scanner.Text()
		}
		if command == "exit" || command == "quit" || command == "q" {
			fmt.Println("quitting...")
			break
		}
		if command == "" {
			fmt.Println()
			continue
		}
		outputFile := fmt.Sprintf("\\\\%s\\C$\\Windows\\Temp\\%s.txt", target, getRandomString(12))
		//cmd := fmt.Sprintf("%%COMSPEC%% /k start /b /wait %%COMSPEC%% %s > %s 2>&1", command, outputFile)
		cmd := fmt.Sprintf("%%COMSPEC%% /c %s > %s 2>&1", command, outputFile)
		batchFile := fmt.Sprintf("\\\\%s\\C$\\Windows\\Temp\\%s.bat", target, getRandomString(18))
		if batch {
			// Make a batch file on the target at C:\Windows\Temp and then we will pass a command to execute this
			f, err := os.Create(batchFile)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			// "C:\Windows\System32\cmd.exe /k start /b /wait \\127.0.0.1\C$\Windows\Temp\1.bat & timeout /t 10"
			f.WriteString(fmt.Sprintf("%s > %s 2>&1", command, outputFile))
			f.Close()
			cmd = fmt.Sprintf("%%COMSPEC%% /k start /b /wait %s", batchFile)
		}
		err = executeRemoteService(target, cmd, username, password, domain, servicename)
		if err != nil {
			if err.Error() != "The service did not respond to the start or control request in a timely fashion." {
				fmt.Println(err.Error())
				continue
			}
		}
		// We loop and check service status every X time period waiting for completion
		for true {
			state, err := checkServiceState(target, username, password, domain, servicename)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			if state == "Stopped" {
				// read output and break
				c, err := readFileToSlice(outputFile)
				if err != nil {
					fmt.Println(err.Error())
					break
				}
				for _, v := range c {
					fmt.Println(v)
				}
				// TODO - Delete File and Batch
				break
			}

		}
	}
	// TODO - Delete Service
}
