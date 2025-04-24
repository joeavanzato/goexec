package main

import (
	"bufio"
	"fmt"
	"github.com/hirochachacha/go-smb2"
	"io"
	"math/rand"
	"net"
	"os"
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

func authenticatedCopy(user string, pass string, domain string, target string, srcFile string, srcData []byte, dest string, share string) error {
	// If username/password/domain are specified, use these for an authenticated SMB transfer
	// Open raw TCP connection to SMB server (port 445)
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
		remoteFile, err := fs.Create("/remote.txt")
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
