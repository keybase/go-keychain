// +build darwin ios

package test

import (
	"testing"

	"github.com/keybase/go-keychain/bind"
)

type test struct {
	t *testing.T
}

func (t test) Fail(s string) {
	t.t.Fatal(s)
}

func TestGenericPassword(t *testing.T) {
	service := "Testing service as unicode テスト"
	accessGroup := ""
	bind.GenericPasswordTest(test{t}, service, accessGroup)
}
