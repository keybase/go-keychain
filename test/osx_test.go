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

func TestGenericPasswordRef(t *testing.T) {
	service, account, label, accessGroup, password := "TestGenericPasswordRef", "test", "", "", "toomanysecrets"

	item := keychain.NewGenericPassword(service, account, label, []byte(password), accessGroup)
	defer keychain.DeleteItem(item)
	err := keychain.AddItem(item)
	if err != nil {
		t.Fatal(err)
	}

	// Query reference and delete by reference
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(service)
	query.SetAccount(account)
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnRef(true)
	ref, err := keychain.QueryItemRef(query)
	if err != nil {
		t.Fatal(err)
	} else if ref == nil {
		t.Fatal("Missing result")
	} else {
		err = keychain.DeleteItemRef(ref)
		if err != nil {
			t.Fatal(err)
		}
		keychain.Release(ref)
	}

	passwordAfter, err := keychain.GetGenericPassword(service, account, label, accessGroup)
	if passwordAfter != nil {
		t.Fatal("Shouldn't have password")
	}
}
