package main

import "syscall"

// Define WNetAddConnection2W parameters
type NETRESOURCE struct {
	dwScope       uint32
	dwType        uint32
	dwDisplayType uint32
	dwUsage       uint32
	lpLocalName   *uint16
	lpRemoteName  *uint16
	lpComment     *uint16
	lpProvider    *uint16
}

// Windows API function pointers
var (
	modadvapi32                 = syscall.NewLazyDLL("advapi32.dll")
	procOpenSCManagerW          = modadvapi32.NewProc("OpenSCManagerW")
	procCreateServiceW          = modadvapi32.NewProc("CreateServiceW")
	procOpenServiceW            = modadvapi32.NewProc("OpenServiceW")
	procStartServiceW           = modadvapi32.NewProc("StartServiceW")
	procQueryServiceStatus      = modadvapi32.NewProc("QueryServiceStatus")
	procCloseServiceHandle      = modadvapi32.NewProc("CloseServiceHandle")
	procDeleteService           = modadvapi32.NewProc("DeleteService")
	procChangeServiceConfigW    = modadvapi32.NewProc("ChangeServiceConfigW")
	procChangeServiceConfig2W   = modadvapi32.NewProc("ChangeServiceConfig2W")
	procControlService          = modadvapi32.NewProc("ControlService")
	procLogonUserW              = modadvapi32.NewProc("LogonUserW")
	procImpersonateLoggedOn     = modadvapi32.NewProc("ImpersonateLoggedOnUser")
	procDuplicateTokenEx        = modadvapi32.NewProc("DuplicateTokenEx")
	procOpenProcessToken        = modadvapi32.NewProc("OpenProcessToken")
	procImpersonateLoggedOnUser = modadvapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf            = modadvapi32.NewProc("RevertToSelf")

	mpr                        = syscall.NewLazyDLL("mpr.dll")
	procWNetAddConnection2W    = mpr.NewProc("WNetAddConnection2W")
	procWNetCancelConnection2W = mpr.NewProc("WNetCancelConnection2W")

	// Load Security Support Provider Interface (SSPI)
	secur32                       = syscall.NewLazyDLL("secur32.dll")
	procAcquireCredentialsHandle  = secur32.NewProc("AcquireCredentialsHandleW")
	procInitializeSecurityContext = secur32.NewProc("InitializeSecurityContextW")
)

const (

	// Security impersonation levels
	SecurityImpersonation = 2

	// Token access rights
	TOKEN_DUPLICATE        = 0x0002
	TOKEN_QUERY            = 0x0008
	TOKEN_ASSIGN_PRIMARY   = 0x0001
	TOKEN_ADJUST_DEFAULT   = 0x0080
	TOKEN_ADJUST_SESSIONID = 0x0100
	TOKEN_ALL_ACCESS       = 0xF01FF

	// CreateProcessWithTokenW options
	STARTF_USESHOWWINDOW = 0x00000001

	// Constants for DuplicateTokenEx
	SecurityIdentification = 1
	SecurityDelegation     = 3
	TokenPrimary           = 1

	// Logon Types
	LOGON32_LOGON_INTERACTIVE       = 2
	LOGON32_LOGON_NETWORK           = 3
	LOGON32_LOGON_BATCH             = 4
	LOGON32_LOGON_NETWORK_CLEARTEXT = 8
	LOGON32_LOGON_NEW_CREDENTIALS   = 9

	// Logon Providers
	LOGON32_PROVIDER_DEFAULT = 0
	LOGON32_PROVIDER_WINNT40 = 2
	LOGON32_PROVIDER_WINNT50 = 3

	// Resource types
	RESOURCETYPE_DISK = 1

	// Connection flags
	CONNECT_INTERACTIVE = 0x00000008
	CONNECT_PROMPT      = 0x00000010
	CONNECT_COMMANDLINE = 0x00000800
	CONNECT_REDIRECTED  = 0x00000080
	CONNECT_TEMPORARY   = 0x00000004

	// Network resource constants
	RESOURCE_CONNECTED = 0x00000001
	RESOURCETYPE_ANY   = 0x00000000
	NO_ERROR           = 0
)
