// Darwin user-presence implementation: LocalAuthentication device-owner
// check (Touch ID with password fallback), blocking until the user
// responds. Built only with cgo on macOS.

//go:build darwin && cgo

package userpresence

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation
#include <stdlib.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Foundation/Foundation.h>

static int cloak_user_presence(const char *reason) {
	LAContext *ctx = [[LAContext alloc] init];
	NSError *err = nil;
	if (![ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&err]) {
		return 2;
	}
	dispatch_semaphore_t sem = dispatch_semaphore_create(0);
	__block int result = 1;
	NSString *r = [NSString stringWithUTF8String:reason];
	[ctx evaluatePolicy:LAPolicyDeviceOwnerAuthentication
	    localizedReason:r
	              reply:^(BOOL ok, NSError *e) {
		result = ok ? 0 : 1;
		dispatch_semaphore_signal(sem);
	}];
	dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
	return result;
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

func require(reason string) error {
	cr := C.CString("git-cloak: " + reason)
	defer C.free(unsafe.Pointer(cr))
	switch C.cloak_user_presence(cr) {
	case 0:
		return nil
	case 2:
		return errors.New("cloak: user-presence check unavailable on this device")
	default:
		return errors.New("cloak: user-presence check failed or was cancelled")
	}
}
