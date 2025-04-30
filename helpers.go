package main

import (
	"bufio"
	"fmt"
	"github.com/hirochachacha/go-smb2"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func getRandomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

// checkExists checks if a file exists at the given path
func checkExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// readFileToSlice reads a file and returns its contents as a slice of strings
func readFileToSlice(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// deleteFile deletes a file at the given path
func deleteFile(filePath string) error {
	return os.Remove(filePath)
}

// UTF16PtrFromString creates a pointer to a UTF16 string
func UTF16PtrFromString(s string) *uint16 {
	ptr, _ := syscall.UTF16PtrFromString(s)
	return ptr
}

func logonUser(username, domain, password string) (syscall.Handle, error) {
	var token syscall.Handle
	ret, _, err := procLogonUserW.Call(
		uintptr(unsafe.Pointer(UTF16PtrFromString(username))),
		uintptr(unsafe.Pointer(UTF16PtrFromString(domain))),
		uintptr(unsafe.Pointer(UTF16PtrFromString(password))),
		uintptr(LOGON32_LOGON_NEW_CREDENTIALS),
		uintptr(LOGON32_PROVIDER_WINNT50),
		uintptr(unsafe.Pointer(&token)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("LogonUserW failed: %v", err)
	}
	return token, nil
}

func impersonateUser(token syscall.Handle) error {
	ret, _, err := procImpersonateLoggedOnUser.Call(uintptr(token))
	if ret == 0 {
		return fmt.Errorf("ImpersonateLoggedOnUser failed: %v", err)
	}
	return nil
}

func revertToSelf() {
	procRevertToSelf.Call()
}

func getAuthenticatedSMBSession(user, pass, domain, target string) (*smb2.Session, net.Conn, error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:445", target))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to SMB server: %v", err)
	}

	// Use NTLM authentication
	dialer := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     user,
			Password: pass,
			Domain:   domain, // Optional: "" if not needed
		},
	}
	session, err := dialer.Dial(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial SMB session: %v", err)
	}
	return session, conn, nil
}

func authenticatedCopy(user string, pass string, domain string, target string, srcFile string, srcData []byte, dest string, share string) error {
	// If username/password/domain are specified, use these for an authenticated SMB transfer
	// Open raw TCP connection to SMB server (port 445)
	fmt.Printf("Copying %s to %s on %s\n", srcFile, dest, target)
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:445", target))
	if err != nil {
		return fmt.Errorf("failed to connect to SMB server: %v", err)
	}
	defer conn.Close()

	// Use NTLM authentication
	dialer := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     user,
			Password: pass,
			Domain:   domain, // Optional: "" if not needed
		},
	}
	session, err := dialer.Dial(conn)
	if err != nil {
		return fmt.Errorf("failed to dial SMB session: %v", err)
	}
	defer session.Logoff()

	/*	sharenames, err := session.ListSharenames()
		if err != nil {
			return fmt.Errorf("failed to list SMB shares: %v", err)
		} else {
			fmt.Println(sharenames)
		}*/

	// fmt.Sprintf("\\\\%s\\%s", target, share)
	fmt.Println(session.ListSharenames())
	fs, err := session.Mount(share)
	if err != nil {
		return fmt.Errorf("failed to mount SMB share: %v", err)
	}
	defer fs.Umount()

	if srcFile != "" {
		// Open local file to upload
		localFile, err := os.Open(srcFile)
		if err != nil {
			return fmt.Errorf("failed to open local file: %v", err)
		}
		defer localFile.Close()
		// Create (or overwrite) the file on SMB share
		remoteFile, err := fs.Create(dest)
		if err != nil {
			return fmt.Errorf("failed to create remote file: %v", err)
		}
		defer remoteFile.Close()

		// Copy contents
		written, err := io.Copy(remoteFile, localFile)
		if err != nil {
			return fmt.Errorf("failed to copy file: %v", err)
		}
		fmt.Printf("Successfully uploaded %d bytes to SMB share.\n", written)
	} else if srcData != nil {
		remoteFile, err := fs.Create(dest)
		if err != nil {
			return fmt.Errorf("failed to create remote file: %v", err)
		}
		defer remoteFile.Close()

		// Write data
		written, err := remoteFile.Write(srcData)
		if err != nil {
			return fmt.Errorf("failed to write data to remote file: %v", err)
		}
		fmt.Printf("Successfully uploaded %d bytes to SMB share.\n", written)
	} else {
		return fmt.Errorf("no source file or data provided")
	}
	return nil
}

func copyFile(srcFile string, srcData []byte, destFull string) error {
	// Using current context
	f, err := os.Create(destFull)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer f.Close()
	if srcData != nil {
		f.Write(srcData)
	}
	if srcFile != "" {
		src, err := os.Open(srcFile)
		if err != nil {
			return fmt.Errorf("failed to open source file: %v", err)
		}
		defer src.Close()
		_, err = io.Copy(f, src)
		if err != nil {
			return fmt.Errorf("failed to copy file: %v", err)
		}
	}
	return nil
}

// Helper function to create a NULL DACL security descriptor
func createNullDaclSD() ([]byte, error) {
	// Initialize necessary DLLs and procedures
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	initializeSecurityDescriptor := advapi32.NewProc("InitializeSecurityDescriptor")
	setSecurityDescriptorDacl := advapi32.NewProc("SetSecurityDescriptorDacl")

	// Create a security descriptor - 20 bytes is the minimum size
	sd := make([]byte, 20) // SECURITY_DESCRIPTOR_MIN_LENGTH

	// Initialize the security descriptor
	ret, _, err := initializeSecurityDescriptor.Call(
		uintptr(unsafe.Pointer(&sd[0])),
		uintptr(1), // SECURITY_DESCRIPTOR_REVISION
	)

	if ret == 0 {
		return nil, fmt.Errorf("InitializeSecurityDescriptor failed: %v", err)
	}

	// Set a NULL DACL - this effectively allows all access
	ret, _, err = setSecurityDescriptorDacl.Call(
		uintptr(unsafe.Pointer(&sd[0])),
		uintptr(1), // bDaclPresent - TRUE
		0,          // NULL for Dacl
		uintptr(0), // bDaclDefaulted - FALSE
	)

	if ret == 0 {
		return nil, fmt.Errorf("SetSecurityDescriptorDacl failed: %v", err)
	}

	return sd, nil
}

func reverseByteSliceCopy(s []byte) []byte {
	newSlice := make([]byte, len(s))
	copy(newSlice, s)

	for i, j := 0, len(newSlice)-1; i < j; i, j = i+1, j-1 {
		newSlice[i], newSlice[j] = newSlice[j], newSlice[i]
	}
	return newSlice
}

// Split username into user and domain parts
func splitUserNameAndDomain(fullUsername string) (string, string) {
	parts := strings.SplitN(fullUsername, "\\", 2)
	if len(parts) == 2 {
		return parts[1], parts[0]
	}

	// Try to split by @ for UPN format
	parts = strings.SplitN(fullUsername, "@", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}

	return fullUsername, ""
}

// EstablishConnection establishes a connection to a remote resource
func EstablishConnection(settings *Settings, resource string, connect bool) bool {
	// TODO - Make sure this works correctly if we don't specify user/password/domain (default process context)
	// Already connected to self
	if settings.Target == "." {
		return true
	}

	remoteResource := fmt.Sprintf("\\\\%s\\%s", settings.Target, resource)

	// Impersonate user if credentials provided
	if settings.UserImpersonated == 0 && settings.User != "" {
		user, domain := splitUserNameAndDomain(settings.User)

		var domainPtr *uint16
		if domain != "" {
			d, _ := syscall.UTF16PtrFromString(domain)
			domainPtr = d
		}

		u, _ := syscall.UTF16PtrFromString(user)
		p, _ := syscall.UTF16PtrFromString(settings.Password)

		var token syscall.Handle

		// Load logon user from advapi32.dll
		advapi32 := syscall.NewLazyDLL("advapi32.dll")
		logonUserW := advapi32.NewProc("LogonUserW")

		r, _, err := logonUserW.Call(
			uintptr(unsafe.Pointer(u)),
			uintptr(unsafe.Pointer(domainPtr)),
			uintptr(unsafe.Pointer(p)),
			uintptr(LOGON32_LOGON_NEW_CREDENTIALS),
			uintptr(LOGON32_PROVIDER_WINNT50),
			uintptr(unsafe.Pointer(&token)),
		)

		if r == 0 {
			fmt.Printf("Failed to log on as remote user %s: %v\n", settings.User, err)
		} else {
			settings.UserImpersonated = token
		}
	}

	if connect {
		// Check if already connected
		if isAlreadyConnected(remoteResource) {
			if strings.Contains(resource, "IPC$") {
				settings.NeedToDetachFromIPC = false
			} else if strings.Contains(resource, settings.TargetShare) {
				settings.NeedToDetachFromAdmin = false
			}
			return true
		}

		// Establish new connection
		mpr := syscall.NewLazyDLL("mpr.dll")
		wNetAddConnection2 := mpr.NewProc("WNetAddConnection2W")

		nr := NETRESOURCE{
			dwType:       RESOURCETYPE_ANY,
			lpRemoteName: syscall.StringToUTF16Ptr(remoteResource),
		}

		var passwordPtr, userPtr *uint16
		if settings.Password != "" {
			passwordPtr = syscall.StringToUTF16Ptr(settings.Password)
		}
		if settings.User != "" {
			userPtr = syscall.StringToUTF16Ptr(settings.User)
		}

		ret, _, _ := wNetAddConnection2.Call(
			uintptr(unsafe.Pointer(&nr)),
			uintptr(unsafe.Pointer(passwordPtr)),
			uintptr(unsafe.Pointer(userPtr)),
			uintptr(0),
		)

		if ret == NO_ERROR {
			if strings.Contains(resource, "IPC$") {
				settings.NeedToDetachFromIPC = true
			} else if strings.Contains(resource, settings.TargetShare) {
				settings.NeedToDetachFromAdmin = true
			}
			return true
		} else {
			fmt.Printf("Failed to connect to %s: %d\n", remoteResource, ret)
			if strings.Contains(resource, "IPC$") {
				settings.NeedToDetachFromIPC = false
			} else if strings.Contains(resource, settings.TargetShare) {
				settings.NeedToDetachFromAdmin = false
			}
			return false
		}
	} else {
		// Disconnect
		mpr := syscall.NewLazyDLL("mpr.dll")
		wNetCancelConnection2 := mpr.NewProc("WNetCancelConnection2W")

		remoteName, _ := syscall.UTF16PtrFromString(remoteResource)
		wNetCancelConnection2.Call(
			uintptr(unsafe.Pointer(remoteName)),
			uintptr(0),
			uintptr(0), // FALSE
		)
		return true
	}
}

// Helper function to check if already connected to the resource
func isAlreadyConnected(remoteResource string) bool {
	mpr := syscall.NewLazyDLL("mpr.dll")
	wNetOpenEnum := mpr.NewProc("WNetOpenEnumW")
	wNetEnumResource := mpr.NewProc("WNetEnumResourceW")
	wNetCloseEnum := mpr.NewProc("WNetCloseEnum")

	var handle uintptr
	ret, _, _ := wNetOpenEnum.Call(
		uintptr(RESOURCE_CONNECTED),
		uintptr(RESOURCETYPE_ANY),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&handle)),
	)

	if ret != NO_ERROR {
		fmt.Println("Not Connected")
		return false
	}
	defer wNetCloseEnum.Call(handle)

	// Buffer for network resources
	const bufferSize = 16384 // 16KB buffer
	buffer := make([]byte, bufferSize)
	var count uint32 = 0xFFFFFFFF // Get as many entries as possible
	var bufSize uint32 = bufferSize

	ret, _, _ = wNetEnumResource.Call(
		handle,
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&bufSize)),
	)

	if ret != NO_ERROR {
		return false
	}

	// Iterate through returned resources
	pNR := (*NETRESOURCE)(unsafe.Pointer(&buffer[0]))
	for i := uint32(0); i < count; i++ {
		// Calculate the offset for the current NETRESOURCE
		nr := (*NETRESOURCE)(unsafe.Pointer(uintptr(unsafe.Pointer(pNR)) + uintptr(i)*unsafe.Sizeof(*pNR)))

		// Convert LPWSTR to Go string for comparison
		if nr.lpRemoteName != nil {
			remoteName := syscall.UTF16ToString((*[1 << 16]uint16)(unsafe.Pointer(nr.lpRemoteName))[:maxUTF16StringLength(nr.lpRemoteName)])
			if strings.EqualFold(remoteName, remoteResource) {
				return true
			}
		}
	}

	return false
}

// Helper function to find null terminator in UTF16 string
func maxUTF16StringLength(ptr *uint16) int {
	if ptr == nil {
		return 0
	}

	// Get a slice to the UTF16 string
	s := (*[1 << 16]uint16)(unsafe.Pointer(ptr))

	// Find the null terminator
	for i := 0; i < (1 << 16); i++ {
		if s[i] == 0 {
			return i
		}
	}

	return (1 << 16) - 1 // Max length if no null found (shouldn't happen)
}
