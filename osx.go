// +build darwin,!ios

package keychain

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import (
	"os"
	"unsafe"
)

var AccessibleKey = attrKey(C.CFTypeRef(C.kSecAttrAccessible))
var accessibleTypeRef = map[Accessible]C.CFTypeRef{
	AccessibleWhenUnlocked:                   C.CFTypeRef(C.kSecAttrAccessibleWhenUnlocked),
	AccessibleAfterFirstUnlock:               C.CFTypeRef(C.kSecAttrAccessibleAfterFirstUnlock),
	AccessibleAlways:                         C.CFTypeRef(C.kSecAttrAccessibleAlways),
	AccessibleWhenUnlockedThisDeviceOnly:     C.CFTypeRef(C.kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
	AccessibleAfterFirstUnlockThisDeviceOnly: C.CFTypeRef(C.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
	AccessibleAccessibleAlwaysThisDeviceOnly: C.CFTypeRef(C.kSecAttrAccessibleAlwaysThisDeviceOnly),

	// Only available in 10.10
	//AccessibleWhenPasscodeSetThisDeviceOnly:  C.CFTypeRef(C.kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly),
}

var (
	AccessKey = attrKey(C.CFTypeRef(C.kSecAttrAccess))
)

// The returned SecAccessRef, if non-nil, must be released via CFRelease.
func createAccess(label string, trustedApplications []string) (C.CFTypeRef, error) {
	if len(trustedApplications) == 0 {
		return nil, nil
	}

	// Always prepend with empty string which signifies that we
	// include a NULL application, which means ourselves.
	trustedApplications = append([]string{""}, trustedApplications...)

	var err error
	var labelRef C.CFStringRef
	if labelRef, err = StringToCFString(label); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(labelRef))

	var trustedApplicationsRefs []C.CFTypeRef
	for _, trustedApplication := range trustedApplications {
		trustedApplicationRef, err := createTrustedApplication(trustedApplication)
		if err != nil {
			return nil, err
		}
		defer C.CFRelease(C.CFTypeRef(trustedApplicationRef))
		trustedApplicationsRefs = append(trustedApplicationsRefs, trustedApplicationRef)
	}

	var access C.SecAccessRef
	trustedApplicationsArray := ArrayToCFArray(trustedApplicationsRefs)
	defer C.CFRelease(C.CFTypeRef(trustedApplicationsArray))
	errCode := C.SecAccessCreate(labelRef, trustedApplicationsArray, &access)
	err = checkError(errCode)
	if err != nil {
		return nil, err
	}

	return C.CFTypeRef(access), nil
}

// The returned SecTrustedApplicationRef, if non-nil, must be released via CFRelease.
func createTrustedApplication(trustedApplication string) (C.CFTypeRef, error) {
	var trustedApplicationCStr *C.char
	if trustedApplication != "" {
		trustedApplicationCStr = C.CString(trustedApplication)
		defer C.free(unsafe.Pointer(trustedApplicationCStr))
	}

	var trustedApplicationRef C.SecTrustedApplicationRef
	errCode := C.SecTrustedApplicationCreateFromPath(trustedApplicationCStr, &trustedApplicationRef)
	err := checkError(errCode)
	if err != nil {
		return nil, err
	}

	return C.CFTypeRef(trustedApplicationRef), nil
}

type Access struct {
	Label               string
	TrustedApplications []string
}

func (a Access) Convert() (C.CFTypeRef, error) {
	return createAccess(a.Label, a.TrustedApplications)
}

func (k *Item) SetAccess(a *Access) {
	if a != nil {
		k.attr[AccessKey] = a
	} else {
		delete(k.attr, AccessKey)
	}
}

// DeleteItemRef deletes a keychain item reference.
func DeleteItemRef(ref C.CFTypeRef) error {
	errCode := C.SecKeychainItemDelete(C.SecKeychainItemRef(ref))
	return checkError(errCode)
}

var (
	KeychainKey = attrKey(C.CFTypeRef(C.kSecUseKeychain))

	MatchSearchListKey = attrKey(C.CFTypeRef(C.kSecMatchSearchList))
)

// Keychain represents the path to a specific OSX keychain
type Keychain struct {
	path string
}

// NewKeychain creates a new keychain file with either a password, or a triggered prompt to the user
func NewKeychain(path, password string, promptUser bool) (Keychain, error) {
	pathRef := C.CString(path)
	defer C.free(unsafe.Pointer(pathRef))

	var errCode C.OSStatus
	var kref C.SecKeychainRef

	if promptUser {
		errCode = C.SecKeychainCreate(pathRef, C.UInt32(0), nil, C.Boolean(1), nil, &kref)
	} else {
		passwordRef := C.CString(password)
		defer C.free(unsafe.Pointer(passwordRef))
		errCode = C.SecKeychainCreate(pathRef, C.UInt32(len(password)), unsafe.Pointer(passwordRef), C.Boolean(0), nil, &kref)
	}

	// TODO: Without passing in kref I get 'One or more parameters passed to the function were not valid (-50)'
	defer Release(C.CFTypeRef(kref))

	if err := checkError(errCode); err != nil {
		return Keychain{}, err
	}

	return Keychain{path}, nil
}

// The returned SecKeychainRef, if non-nil, must be released via CFRelease.
func openKeychainRef(path string) (C.SecKeychainRef, error) {
	pathName := C.CString(path)
	defer C.free(unsafe.Pointer(pathName))

	var kref C.SecKeychainRef
	if err := checkError(C.SecKeychainOpen(pathName, &kref)); err != nil {
		return nil, err
	}

	return kref, nil
}

func (kc *Keychain) Delete() error {
	return os.Remove(kc.path)
}

// The returned CFTypeRef, if non-nil, must be released via CFRelease.
func (kc Keychain) Convert() (C.CFTypeRef, error) {
	keyRef, err := openKeychainRef(kc.path)
	return C.CFTypeRef(keyRef), err
}

type keychainArray []Keychain

// The returned CFTypeRef, if non-nil, must be released via CFRelease.
func (ka keychainArray) Convert() (C.CFTypeRef, error) {
	var refs = make([]C.CFTypeRef, len(ka))
	var err error

	for idx, kc := range ka {
		if refs[idx], err = kc.Convert(); err != nil {
			for _, ref := range refs {
				if ref != nil {
					Release(ref)
				}
			}
			return nil, err
		}
	}

	return C.CFTypeRef(ArrayToCFArray(refs)), nil
}

// extensions of Item for OSX specific features

func (k *Item) SetMatchSearchList(karr ...Keychain) {
	k.attr[MatchSearchListKey] = keychainArray(karr)
}

func (k *Item) UseKeychain(kc Keychain) {
	k.attr[KeychainKey] = kc
}
