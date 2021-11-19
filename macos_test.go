//go:build darwin && !ios
// +build darwin,!ios

package keychain

import (
	"fmt"
	"testing"
)

func TestUpdateItem(t *testing.T) {
	var err error

	item := NewGenericPassword("TestAccess", "firsttest", "TestUpdateItem", []byte("toomanysecrets2"), "")
	defer func() { _ = DeleteItem(item) }()
	err = AddItem(item)
	if err != nil {
		t.Fatal(err)
	}

	data1, err := GetGenericPassword("TestAccess", "firsttest", "TestUpdateItem", "")
	if err != nil {
		t.Fatal(err)
	}
	if string(data1) != "toomanysecrets2" {
		t.Fatal("TestUpdateItem: new password does not match")
	}

	updateItem := NewItem()
	updateItem.SetSecClass(SecClassGenericPassword)
	updateItem.SetService("TestAccess")
	updateItem.SetAccount("firsttest")
	updateItem.SetLabel("TestUpdateItem")
	updateItem.SetData([]byte("toomanysecrets3"))
	err = UpdateItem(item, updateItem)
	if err != nil {
		t.Fatal(err)
	}

	data2, err := GetGenericPassword("TestAccess", "firsttest", "TestUpdateItem", "")
	if err != nil {
		t.Fatal(err)
	}
	if string(data2) != "toomanysecrets3" {
		t.Fatal("TestUpdateItem: updated password does not match")
	}
}

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
	} else if ref == 0 {
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

func TestInternetPassword(t *testing.T) {
	query := NewItem()
	query.SetSecClass(SecClassInternetPassword)
	query.SetLabel("github.com")
	query.SetMatchLimit(MatchLimitOne)
	query.SetReturnAttributes(true)
	results, err := QueryItem(query)
	if err != nil {
		// Error
		t.Errorf("Query Error: %v", err)
	} else {
		for _, r := range results {
			fmt.Printf("%#v\n", r.Account)
		}
	}
}
