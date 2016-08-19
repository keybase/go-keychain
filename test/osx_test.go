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

func TestUpdateItem(t *testing.T) {
	var err error

	item := keychain.NewGenericPassword("TestAccess", "firsttest", "TestUpdateItem", []byte("toomanysecrets2"), "")
	defer keychain.DeleteItem(item)
	err = keychain.AddItem(item)
	if err != nil {
		t.Fatal(err)
	}

	data1, err := keychain.GetGenericPassword("TestAccess", "firsttest", "TestUpdateItem", "")
	if err != nil {
		t.Fatal(err)
	}
	if string(data1) != "toomanysecrets2" {
		t.Fatal("TestUpdateItem: new password does not match")
	}

	updateItem := keychain.NewItem()
	updateItem.SetSecClass(keychain.SecClassGenericPassword)
	updateItem.SetService("TestAccess")
	updateItem.SetAccount("firsttest")
	updateItem.SetLabel("TestUpdateItem")
	updateItem.SetData([]byte("toomanysecrets3"))
	err = keychain.UpdateItem(item, updateItem)
	if err != nil {
		t.Fatal(err)
	}

	data2, err := keychain.GetGenericPassword("TestAccess", "firsttest", "TestUpdateItem", "")
	if err != nil {
		t.Fatal(err)
	}
	if string(data2) != "toomanysecrets3" {
		t.Fatal("TestUpdateItem: updated password does not match")
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
