// +build darwin ios

package keychain

/*
#cgo LDFLAGS: -framework CoreFoundation

#include <CoreFoundation/CoreFoundation.h>
*/
import "C"
import "time"

func releaseCFDateForTest(d C.CFDateRef) {
	Release(C.CFTypeRef(d))
}

func TimeToCFDate(t time.Time) (C.CFDateRef, error) {
	panic("Unimplemented")
}

func CFDateToTime(d C.CFDateRef) (time.Time, error) {
	panic("Unimplemented")
}
