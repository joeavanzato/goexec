package main

import (
	"bufio"
	"fmt"
	"math/rand"
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
