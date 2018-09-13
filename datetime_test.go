// +build darwin,!ios

package keychain

import (
	"math"
	"testing"
	"time"
)

// Test time is 2018-09-13T06:08:49+00:00
const (
	// Number of seconds between the test time and the Unix epoch
	// (1970-01-01T00:00:00+00:00).
	testTimeUnixSeconds = 1536818929
	// Number of seconds between the test time and
	// CoreFoundation's absolute reference date
	// (1 Jan 2001  00:00:00 GMT). See
	// https://developer.apple.com/documentation/corefoundation/cfabsolutetime?language=objc
	testTimeAbsoluteTimeSeconds = 558511729
)

func TestUnixToAbsoluteTime(t *testing.T) {
	var testNano int64 = 123456789
	abs := unixToAbsoluteTime(testTimeUnixSeconds, testNano)
	int, frac := math.Modf(float64(abs))
	s := int64(int)
	ns := int64(frac * nsPerSec)
	if s != testTimeAbsoluteTimeSeconds {
		t.Fatalf("expected %d, got %d", testTimeAbsoluteTimeSeconds, s)
	}
	if ns != testNano {
		t.Fatalf("expected %d, got %d", testNano, ns)
	}
}

func TestTimeToCFDateToTime(t *testing.T) {
	// 2018-09-13T06:08:49.123456789+00:00
	tm := time.Unix(1536818929, 123456789)
	date := TimeToCFDate(tm)
	t.Logf("date is %s", cfDateToString(date))
	defer releaseCFDateForTest(date)

	tm2 := CFDateToTime(date)

	if tm != tm2 {
		t.Fatalf("expected %s, got %s", tm, tm2)
	}
}
