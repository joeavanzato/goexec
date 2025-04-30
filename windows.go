package main

import (
	"github.com/go-ole/go-ole"
	"syscall"
)

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

	// OLE32.dll for COM functions
	modOle32                 = syscall.NewLazyDLL("ole32.dll")
	procCoInitializeEx       = modOle32.NewProc("CoInitializeEx")
	procCoInitializeSecurity = modOle32.NewProc("CoInitializeSecurity")
	procCoUninitialize       = modOle32.NewProc("CoUninitialize")
	procCoCreateInstance     = modOle32.NewProc("CoCreateInstance")
	procCoCreateInstanceEx   = modOle32.NewProc("CoCreateInstanceEx")
	procCLSIDFromProgID      = modOle32.NewProc("CLSIDFromProgID")
	procCoSetProxyBlanket    = modOle32.NewProc("CoSetProxyBlanket")
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

	// COM constants if not provided by the ole package
	CLSCTX_INPROC_SERVER  = 0x1
	CLSCTX_INPROC_HANDLER = 0x2
	CLSCTX_LOCAL_SERVER   = 0x4
	CLSCTX_REMOTE_SERVER  = 0x10
	CLSCTX_ALL            = CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER | CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER

	// RPC Authentication levels
	RPC_C_AUTHN_LEVEL_DEFAULT       = 0
	RPC_C_AUTHN_LEVEL_NONE          = 1
	RPC_C_AUTHN_LEVEL_CONNECT       = 2
	RPC_C_AUTHN_LEVEL_CALL          = 3
	RPC_C_AUTHN_LEVEL_PKT           = 4
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 5
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY   = 6

	// RPC Authentication services
	RPC_C_AUTHN_WINNT        = 10
	RPC_C_AUTHN_GSS_KERBEROS = 16

	// RPC Authorization services
	RPC_C_AUTHZ_NONE = 0

	// RPC Impersonation levels
	RPC_C_IMP_LEVEL_DEFAULT     = 0
	RPC_C_IMP_LEVEL_ANONYMOUS   = 1
	RPC_C_IMP_LEVEL_IDENTIFY    = 2
	RPC_C_IMP_LEVEL_IMPERSONATE = 3
	RPC_C_IMP_LEVEL_DELEGATE    = 4

	// EOLE Authentication capabilities
	EOAC_NONE             = 0x0
	EOAC_DYNAMIC_CLOAKING = 0x40

	// Authentication Identity flags
	SEC_WINNT_AUTH_IDENTITY_ANSI    = 1
	SEC_WINNT_AUTH_IDENTITY_UNICODE = 2
)

// COSERVERINFO is used to specify the remote server for COM initialization
type COSERVERINFO struct {
	dwReserved1 uint32
	pwszName    *uint16
	pAuthInfo   uintptr
	dwReserved2 uint32
}

// MULTI_QI is used for multiple interface queries in CoCreateInstanceEx
type MULTI_QI struct {
	iid     *ole.GUID
	punk    uintptr
	hresult uint32
}

// SEC_WINNT_AUTH_IDENTITY_W structure for authentication identity
type SEC_WINNT_AUTH_IDENTITY_W struct {
	User           *uint16
	UserLength     uint32
	Domain         *uint16
	DomainLength   uint32
	Password       *uint16
	PasswordLength uint32
	Flags          uint32
}

// COAUTHINFO structure for COM authentication
type COAUTHINFO struct {
	dwAuthnSvc           uint32
	dwAuthzSvc           uint32
	pwszServerPrincName  *uint16
	dwAuthnLevel         uint32
	dwImpersonationLevel uint32
	pAuthIdentityData    uintptr
	dwCapabilities       uint32
}
