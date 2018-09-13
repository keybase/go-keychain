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

const nsPerSec = 1000000000

func absoluteTimeIntervalSince1970() int64 {
	return int64(C.kCFAbsoluteTimeIntervalSince1970)
}

func unixToAbsoluteTime(s int64, ns int64) C.CFAbsoluteTime {
	abs := s - absoluteTimeIntervalSince1970()
	return C.CFAbsoluteTime(abs) + C.CFTimeInterval(ns)/nsPerSec
}

func absoluteTimeToUnix(abs C.CFAbsoluteTime) (int64, int64) {
	int, frac := math.Modf(float64(abs))
	return int64(int) + absoluteTimeIntervalSince1970(), int64(frac * nsPerSec)
}

func absoluteTimeToDebugString(abs C.CFAbsoluteTime) string {
	dateFormatter := C.CFDateFormatterCreate(C.kCFAllocatorDefault, C.CFLocaleCopyCurrent(), C.kCFDateFormatterFullStyle, C.kCFDateFormatterFullStyle)
	defer Release(C.CFTypeRef(dateFormatter))
	cfStr := C.CFDateFormatterCreateStringWithAbsoluteTime(C.kCFAllocatorDefault, dateFormatter, abs)
	defer Release(C.CFTypeRef(cfStr))
	return CFStringToString(cfStr)
}

func cfDateToDebugString(d C.CFDateRef) string {
	dateFormatter := C.CFDateFormatterCreate(C.kCFAllocatorDefault, C.CFLocaleCopyCurrent(), C.kCFDateFormatterFullStyle, C.kCFDateFormatterFullStyle)
	defer Release(C.CFTypeRef(dateFormatter))
	cfStr := C.CFDateFormatterCreateStringWithDate(C.kCFAllocatorDefault, dateFormatter, d)
	defer Release(C.CFTypeRef(cfStr))
	return CFStringToString(cfStr)
}

func TimeToCFDate(t time.Time) C.CFDateRef {
	s := t.Unix()
	ns := int64(t.Nanosecond())
	abs := unixToAbsoluteTime(s, ns)
	return C.CFDateCreate(C.kCFAllocatorDefault, abs)
}

func CFDateToTime(d C.CFDateRef) time.Time {
	abs := C.CFDateGetAbsoluteTime(d)
	s, ns := absoluteTimeToUnix(abs)
	return time.Unix(s, ns)
}

func cfDateToAbsoluteTime(d C.CFDateRef) C.CFAbsoluteTime {
	return C.CFDateGetAbsoluteTime(d)
}

func absoluteTimeToCFDate(abs C.CFAbsoluteTime) C.CFDateRef {
	return C.CFDateCreate(C.kCFAllocatorDefault, abs)
}

func releaseCFDate(d C.CFDateRef) {
	Release(C.CFTypeRef(d))
}
