// +build darwin ios

package keychain

/*
#cgo LDFLAGS: -framework CoreFoundation

#include <CoreFoundation/CoreFoundation.h>
*/
import "C"
import (
	"math"
	"time"
)

func releaseCFDateForTest(d C.CFDateRef) {
	Release(C.CFTypeRef(d))
}

func TimeToCFDate(t time.Time) (C.CFDateRef, error) {
	unixNano := t.UnixNano()
	abs := C.CFAbsoluteTime(unixNano)/1000000000 + C.kCFAbsoluteTimeIntervalSince1970
	return C.CFDateCreate(C.kCFAllocatorDefault, abs), nil
}

func CFDateToTime(d C.CFDateRef) (time.Time, error) {
	abs := C.CFDateGetAbsoluteTime(d)
	unix := float64(abs - C.kCFAbsoluteTimeIntervalSince1970)
	int, frac := math.Modf(unix)
	s := int64(int)
	ns := int64(frac * 1000000000)
	return time.Unix(s, ns), nil
}
