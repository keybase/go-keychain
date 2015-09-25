// +build darwin ios

package bind

import "testing"

func TestBind(t *testing.T) {
	service := "Testing service as unicode テスト"
	accessGroup := ""
	err := TestGenericPassword(service, accessGroup)
	if err != nil {
		t.Fatal(err)
	}
}
