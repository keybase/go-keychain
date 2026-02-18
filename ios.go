//go:build darwin && ios

package keychain

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import "fmt"

var AccessibleKey = attrKey(C.CFTypeRef(C.kSecAttrAccessible))
var accessibleTypeRef = map[Accessible]C.CFTypeRef{
	AccessibleWhenUnlocked:                   C.CFTypeRef(C.kSecAttrAccessibleWhenUnlocked),
	AccessibleAfterFirstUnlock:               C.CFTypeRef(C.kSecAttrAccessibleAfterFirstUnlock),
	AccessibleAlways:                         C.CFTypeRef(C.kSecAttrAccessibleAlways),
	AccessibleWhenPasscodeSetThisDeviceOnly:  C.CFTypeRef(C.kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly),
	AccessibleWhenUnlockedThisDeviceOnly:     C.CFTypeRef(C.kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
	AccessibleAfterFirstUnlockThisDeviceOnly: C.CFTypeRef(C.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
	AccessibleAccessibleAlwaysThisDeviceOnly: C.CFTypeRef(C.kSecAttrAccessibleAlwaysThisDeviceOnly),
}

// AccessControlKey is key for kSecAttrAccessControl
var AccessControlKey = attrKey(C.CFTypeRef(C.kSecAttrAccessControl))

// AccessControlFlag is a bitmask for SecAccessControlCreateFlags.
type AccessControlFlag = C.SecAccessControlCreateFlags

// Access control flag constants for use with SetAccessControl.
var (
	// AccessControlUserPresence constrains access with either biometry or passcode.
	AccessControlUserPresence = AccessControlFlag(C.kSecAccessControlUserPresence)
	// AccessControlBiometryAny constrains access with Touch ID for any enrolled finger.
	AccessControlBiometryAny = AccessControlFlag(C.kSecAccessControlBiometryAny)
	// AccessControlBiometryCurrentSet constrains access with Touch ID for currently enrolled fingers.
	AccessControlBiometryCurrentSet = AccessControlFlag(C.kSecAccessControlBiometryCurrentSet)
	// AccessControlDevicePasscode constrains access with the device passcode.
	AccessControlDevicePasscode = AccessControlFlag(C.kSecAccessControlDevicePasscode)
	// AccessControlWatch constrains access with Apple Watch.
	AccessControlWatch = AccessControlFlag(C.kSecAccessControlWatch)
	// AccessControlOr allows satisfying any single constraint.
	AccessControlOr = AccessControlFlag(C.kSecAccessControlOr)
	// AccessControlAnd requires satisfying all constraints.
	AccessControlAnd = AccessControlFlag(C.kSecAccessControlAnd)
	// AccessControlPrivateKeyUsage enables using a private key for signing/decryption operations.
	AccessControlPrivateKeyUsage = AccessControlFlag(C.kSecAccessControlPrivateKeyUsage)
	// AccessControlApplicationPassword requires an application-provided password for access.
	AccessControlApplicationPassword = AccessControlFlag(C.kSecAccessControlApplicationPassword)
)

// SetAccessControl sets the access control for the item with a protection level and flags.
// This replaces SetAccessible when you need biometric protection.
// Protection should be one of the Accessible constants (e.g., AccessibleWhenPasscodeSetThisDeviceOnly).
// Flags should be a bitmask of AccessControlFlag values (e.g., AccessControlBiometryCurrentSet).
//
// Note: kSecAttrAccessControl and kSecAttrAccessible are mutually exclusive.
// This method removes any previously set kSecAttrAccessible value.
func (k *Item) SetAccessControl(accessible Accessible, flags AccessControlFlag) error {
	protection, ok := accessibleTypeRef[accessible]
	if !ok {
		return fmt.Errorf("invalid accessible value: %d", accessible)
	}

	var cerr C.CFErrorRef
	access := C.SecAccessControlCreateWithFlags(
		C.kCFAllocatorDefault,
		C.CFTypeRef(protection),
		C.SecAccessControlCreateFlags(flags),
		&cerr,
	)
	if access == 0 {
		if cerr != 0 {
			defer C.CFRelease(C.CFTypeRef(cerr))
			return fmt.Errorf("SecAccessControlCreateWithFlags failed: %d", C.CFErrorGetCode(cerr))
		}
		return fmt.Errorf("SecAccessControlCreateWithFlags failed with unknown error")
	}

	// kSecAttrAccessControl and kSecAttrAccessible are mutually exclusive.
	delete(k.attr, AccessibleKey)

	// Release any previous SecAccessControlRef to avoid leaking CF objects.
	if old, exists := k.attr[AccessControlKey]; exists {
		C.CFRelease(C.CFTypeRef(old.(C.CFTypeRef)))
	}

	k.attr[AccessControlKey] = C.CFTypeRef(access)
	return nil
}

// SetUseDataProtectionKeychain is a no-op on iOS since iOS always uses
// the data protection keychain.
func (k *Item) SetUseDataProtectionKeychain(b bool) {
	// iOS always uses data protection keychain; this is a no-op for API compatibility.
}
