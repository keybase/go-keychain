// +build darwin,!ios

package keychain

import (
	"testing"
	"time"
)

func TestUnixToAbsoluteTime(t *testing.T) {
	// 2018-09-13T06:08:49.123456789+00:00
	var s int64 = 1536818929
	var ns int64 = 123456789
	abs := unixToAbsoluteTime(s, ns)
	t.Logf("date is %s", absoluteTimeToString(abs))
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
