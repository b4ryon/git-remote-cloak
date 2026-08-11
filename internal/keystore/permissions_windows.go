//go:build windows

// Windows key-file ACL validation.
package keystore

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func checkKeyFilePermissions(path string, _ os.FileInfo) error {
	return validateKeyFileACL(path)
}

// validateKeyFileACL permits only the current user, LocalSystem, and the local
// Administrators group. LocalSystem and Administrators are the Windows
// equivalents of root access to a Unix mode-0600 file.
func validateKeyFileACL(path string) error {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read key file ACL: %w", err)
	}
	if sd == nil {
		return fmt.Errorf("%s has no security descriptor", path)
	}

	allowed, err := allowedKeyFileSIDs()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read key file owner: %w", err)
	}
	if owner == nil || !owner.Equals(allowed[0]) {
		return fmt.Errorf("%s is not owned by the current Windows user", path)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read key file DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("%s has no DACL; refusing a key file accessible to everyone", path)
	}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return fmt.Errorf("read key file DACL entry %d: %w", i, err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !aceSID.IsValid() {
				return fmt.Errorf("%s has an invalid SID in DACL entry %d", path, i)
			}
			if !sidAllowed(aceSID, allowed) {
				return fmt.Errorf("%s ACL grants access to untrusted SID %s", path, aceSID.String())
			}
		default:
			return fmt.Errorf("%s has unsupported DACL entry type %d", path, ace.Header.AceType)
		}
	}
	return nil
}

func sidAllowed(sid *windows.SID, allowed []*windows.SID) bool {
	for _, candidate := range allowed {
		if sid.Equals(candidate) {
			return true
		}
	}
	return false
}

func allowedKeyFileSIDs() ([]*windows.SID, error) {
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("get current user SID: %w", err)
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, fmt.Errorf("create LocalSystem SID: %w", err)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, fmt.Errorf("create Administrators SID: %w", err)
	}
	return []*windows.SID{currentUser.User.Sid, systemSID, adminSID}, nil
}
