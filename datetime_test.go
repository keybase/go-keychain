// +build darwin,!ios

package keychain

import (
	"testing"
	"time"
)

func TestTimeToCFDateToTime(t *testing.T) {
	// 2018-09-13T06:08:49.123456789+00:00
	tm := time.Unix(1536818929, 123456789)
	date := TimeToCFDate(tm)
	defer releaseCFDateForTest(date)

	tm2 := CFDateToTime(date)

	if tm != tm2 {
		t.Fatalf("expected %s, got %s", tm, tm2)
	}
}
