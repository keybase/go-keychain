//go:build darwin && !ios
// +build darwin,!ios

package keychain

import (
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

func TestGenericPassword(t *testing.T) {
	service, account, label, accessGroup, password := "TestGenericPasswordRef", "test", "", "", "toomanysecrets"

	item := NewGenericPassword(service, account, label, []byte(password), accessGroup)
	defer func() { _ = DeleteItem(item) }()
	err := AddItem(item)
	if err != nil {
		t.Fatal(err)
	}

	err = DeleteItem(item)
	if err != nil {
		t.Fatal(err)
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
	item := NewItem()
	item.SetSecClass(SecClassInternetPassword)

	// Internet password-specific attributes
	item.SetProtocol("htps")
	item.SetServer("8xs8h5x5dfc0AI5EzT81l.com")
	item.SetPort(1234)
	item.SetPath("/this/is/the/path")

	item.SetAccount("this-is-the-username")
	item.SetLabel("this is the label")
	item.SetData([]byte("this is the password"))
	item.SetComment("this is the comment")
	defer func() { _ = DeleteItem(item) }()
	err := AddItem(item)
	if err != nil {
		t.Fatal(err)
	}

	query := NewItem()
	query.SetSecClass(SecClassInternetPassword)
	query.SetServer("8xs8h5x5dfc0AI5EzT81l.com")
	query.SetMatchLimit(MatchLimitOne)
	query.SetReturnAttributes(true)
	results, err := QueryItem(query)
	if err != nil {
		t.Fatalf("Query Error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.Protocol != "htps" {
		t.Errorf("expected protocol 'htps' but got %q", r.Protocol)
	}
	if r.Server != "8xs8h5x5dfc0AI5EzT81l.com" {
		t.Errorf("expected server '8xs8h5x5dfc0AI5EzT81l.com' but got %q", r.Server)
	}
	if r.Port != 1234 {
		t.Errorf("expected port '1234' but got %d", r.Port)
	}
	if r.Path != "/this/is/the/path" {
		t.Errorf("expected path '/this/is/the/path' but got %q", r.Path)
	}

	if r.Account != "this-is-the-username" {
		t.Errorf("expected account 'this-is-the-username' but got %q", r.Account)
	}
	if r.Label != "this is the label" {
		t.Errorf("expected label 'this is the label' but got %q", r.Label)
	}
	if r.Comment != "this is the comment" {
		t.Errorf("expected comment 'this is the comment' but got %q", r.Comment)
	}
}
