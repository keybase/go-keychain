// +build darwin,!ios
// +build !go1.10

// TODO: Remove this file once we've completely migrated to go 1.10.x.

package keychain

import "testing"

func TestGenericPasswordRef(t *testing.T) {
	service, account, label, accessGroup, password := "TestGenericPasswordRef", "test", "", "", "toomanysecrets"

	item := NewGenericPassword(service, account, label, []byte(password), accessGroup)
	defer func() { _ = DeleteItem(item) }()
	err := AddItem(item)
	if err != nil {
		t.Fatal(err)
	}

	// Query reference and delete by reference
	query := NewItem()
	query.SetSecClass(SecClassGenericPassword)
	query.SetService(service)
	query.SetAccount(account)
	query.SetMatchLimit(MatchLimitOne)
	query.SetReturnRef(true)
	ref, err := QueryItemRef(query)
	if err != nil {
		t.Fatal(err)
	} else if ref == nil {
		t.Fatal("Missing result")
	} else {
		err = DeleteItemRef(ref)
		if err != nil {
			t.Fatal(err)
		}
		Release(ref)
	}

	passwordAfter, err := GetGenericPassword(service, account, label, accessGroup)
	if err != nil {
		t.Fatal(err)
	}
	if passwordAfter != nil {
		t.Fatal("Shouldn't have password")
	}
}
