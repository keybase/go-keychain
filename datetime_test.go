// +build darwin,!ios

package keychain

import (
	"testing"
	"time"
)

func TestTimeToCFDateToTime(t *testing.T) {
	// 2018-09-13T06:08:49.999999999+00:00
	tm := time.Unix(1536818929, 999999999)
	date, err := TimeToCFDate(tm)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseCFDateForTest(date)

	tm2, err := CFDateToTime(date)
	if err != nil {
		t.Fatal(err)
	}

	if tm != tm2 {
		t.Fatalf("expected %s, got %s", tm, tm2)
	}
}
