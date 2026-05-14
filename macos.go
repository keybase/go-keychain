//go:build darwin && !ios
// +build darwin,!ios

package keychain

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// goKeychainUseDataProtectionKeychainKey returns kSecUseDataProtectionKeychain
// when running on macOS 10.15 or later. That symbol is annotated
// API_AVAILABLE(macos(10.15)), so on older systems it is weak-imported and is
// NULL at runtime. The __builtin_available guard ensures we only read it when
// it actually exists; otherwise referencing it during package init would pass
// NULL to CFStringToString and crash the whole package.
static CFStringRef goKeychainUseDataProtectionKeychainKey(void) {
	if (__builtin_available(macOS 10.15, *)) {
		return kSecUseDataProtectionKeychain;
	}
	return NULL;
}

// goKeychainDataProtectionKeychainAvailable reports whether the running macOS
// version provides the data protection keychain (macOS 10.15+). It checks the
// OS version directly rather than inferring it from whether the key resolved,
// so callers can distinguish "OS too old" from "binding broken".
static int goKeychainDataProtectionKeychainAvailable(void) {
	if (__builtin_available(macOS 10.15, *)) {
		return 1;
	}
	return 0;
}
*/
import "C"

// AccessibleKey is key for kSecAttrAccessible
var (
	AccessibleKey     = attrKey(C.CFTypeRef(C.kSecAttrAccessible))
	accessibleTypeRef = map[Accessible]C.CFTypeRef{
		AccessibleWhenUnlocked:                   C.CFTypeRef(C.kSecAttrAccessibleWhenUnlocked),
		AccessibleAfterFirstUnlock:               C.CFTypeRef(C.kSecAttrAccessibleAfterFirstUnlock),
		AccessibleAlways:                         C.CFTypeRef(C.kSecAttrAccessibleAlways),
		AccessibleWhenUnlockedThisDeviceOnly:     C.CFTypeRef(C.kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
		AccessibleAfterFirstUnlockThisDeviceOnly: C.CFTypeRef(C.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
		AccessibleAccessibleAlwaysThisDeviceOnly: C.CFTypeRef(C.kSecAttrAccessibleAlwaysThisDeviceOnly),

		// Only available in 10.10
		// AccessibleWhenPasscodeSetThisDeviceOnly:  C.CFTypeRef(C.kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly),
	}
)

// UseDataProtectionKeychainKey is the attribute key for
// kSecUseDataProtectionKeychain. It is empty on macOS versions older than
// 10.15, where that key is unavailable.
var UseDataProtectionKeychainKey = resolveUseDataProtectionKeychainKey()

func resolveUseDataProtectionKeychainKey() string {
	ref := C.goKeychainUseDataProtectionKeychainKey()
	if ref == 0 {
		return ""
	}
	return CFStringToString(ref)
}

// dataProtectionKeychainAvailable reports whether the running macOS version
// (10.15+) provides the kSecUseDataProtectionKeychain key.
func dataProtectionKeychainAvailable() bool {
	return C.goKeychainDataProtectionKeychainAvailable() != 0
}

// SetUseDataProtectionKeychain controls whether the operation targets the data
// protection keychain (the iOS-style keychain) instead of the legacy
// file-based keychain. The two are separate stores, so this should be set
// consistently across the add, query, update, and delete calls for an item.
// Requires macOS 10.15+; on older versions the kSecUseDataProtectionKeychain
// key is unavailable and this is a no-op.
func (k *Item) SetUseDataProtectionKeychain(b bool) {
	if UseDataProtectionKeychainKey == "" {
		return
	}
	k.attr[UseDataProtectionKeychainKey] = b
}
