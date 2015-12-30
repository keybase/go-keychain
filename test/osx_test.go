// +build darwin,!ios

package test

import (
	"testing"

	"github.com/keybase/go-keychain"
)

func TestAccess(t *testing.T) {
	var err error

	item := keychain.NewGenericPassword("TestAccess", "test2", "A label", []byte("toomanysecrets2"), "")
	defer keychain.DeleteItem(item)

	trustedApplications := []string{"/Applications/Mail.app"}
	item.SetAccess(&keychain.Access{Label: "Mail", TrustedApplications: trustedApplications})
	err = keychain.AddItem(item)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetGenericPassword(t *testing.T) {
	password, err := keychain.GetGenericPassword("TestGetGenericPassword", "test", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if password != nil {
		t.Fatal("Should be nil")
	}
}
