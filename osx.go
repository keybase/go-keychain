// +build darwin,!ios

package keychain

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

var (
	AccessKey = C.CFTypeRef(C.kSecAttrAccess)
)
