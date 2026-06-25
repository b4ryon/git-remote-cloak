// Darwin native Keychain backend (Security.framework via cgo): stores the
// master key as a generic password in the login keychain. The item's
// default ACL is bound to the creating application, which is what the
// dropped /usr/bin/security shell-out could not provide. Reads are silent
// in a logged-in session, so launchd sync never prompts; the sensitive CLI
// operations are additionally gated by the userpresence package.

//go:build darwin && cgo

package keystore

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

static OSStatus cloak_kc_add(const char *service, const char *account, const void *data, size_t len) {
	return SecKeychainAddGenericPassword(NULL,
		(UInt32)strlen(service), service,
		(UInt32)strlen(account), account,
		(UInt32)len, data, NULL);
}

static OSStatus cloak_kc_find(const char *service, const char *account, void **data, UInt32 *len, SecKeychainItemRef *item) {
	return SecKeychainFindGenericPassword(NULL,
		(UInt32)strlen(service), service,
		(UInt32)strlen(account), account,
		len, data, item);
}

static void cloak_kc_free(void *data) {
	if (data) SecKeychainItemFreeContent(NULL, data);
}

static OSStatus cloak_kc_delete(const char *service, const char *account) {
	SecKeychainItemRef item = NULL;
	UInt32 len = 0;
	void *data = NULL;
	OSStatus st = cloak_kc_find(service, account, &data, &len, &item);
	if (st != errSecSuccess) return st;
	cloak_kc_free(data);
	st = SecKeychainItemDelete(item);
	CFRelease(item);
	return st;
}
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
)

// keychainService namespaces cloak's keychain items.
const keychainService = "git-remote-cloak"

func init() {
	keychainAvailable = true
	keychainLoad = kcLoad
	keychainSave = kcSave
	keychainDelete = kcDelete
}

func kcSave(name string, data []byte) error {
	if len(data) == 0 {
		return cloakerr.Newf(cloakerr.KeyUnavailable, "save key to keychain", "empty key data")
	}
	service, account := C.CString(keychainService), C.CString(name)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	st := C.cloak_kc_add(service, account, unsafe.Pointer(&data[0]), C.size_t(len(data)))
	switch st {
	case C.errSecSuccess:
		return nil
	case C.errSecDuplicateItem:
		return cloakerr.New(cloakerr.KeyUnavailable, "save key to keychain",
			fmt.Errorf("keychain item %q already exists; refusing to overwrite a key: %w", name, ErrKeyExists))
	default:
		return cloakerr.Newf(cloakerr.KeyUnavailable, "save key to keychain",
			"SecKeychainAddGenericPassword status %d", int(st))
	}
}

func kcLoad(name string) ([]byte, error) {
	service, account := C.CString(keychainService), C.CString(name)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	var data unsafe.Pointer
	var length C.UInt32
	st := C.cloak_kc_find(service, account, &data, &length, nil)
	if st != C.errSecSuccess {
		return nil, cloakerr.Newf(cloakerr.KeyUnavailable, "load key from keychain",
			"keychain item %q unavailable (status %d); run `git cloak keygen` or `git cloak key import`", name, int(st))
	}
	defer C.cloak_kc_free(data)
	// length is the keychain item's own byte count (our master key, far under
	// 2 GiB) and C.GoBytes requires a C.int. gosec G115 flags this cgo uint32
	// -> int32 conversion on darwin; inline #nosec cannot suppress it because
	// cgo strips comments before gosec analyzes the generated file, so it is
	// excluded at the linter-config level instead.
	out := C.GoBytes(data, C.int(length))
	return out, nil
}

func kcDelete(name string) error {
	service, account := C.CString(keychainService), C.CString(name)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	if st := C.cloak_kc_delete(service, account); st != C.errSecSuccess {
		return cloakerr.Newf(cloakerr.KeyUnavailable, "delete keychain item",
			"status %d", int(st))
	}
	return nil
}
