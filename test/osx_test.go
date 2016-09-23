// +build darwin,!ios

package test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keybase/go-keychain"
)

func TestAccess(t *testing.T) {
	var err error

	item := keychain.NewGenericPassword("TestAccess", "test2", "A label", []byte("toomanysecrets2"), "")
	defer func() { _ = keychain.DeleteItem(item) }()

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
	defer func() { _ = keychain.DeleteItem(item) }()
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
	defer func() { _ = keychain.DeleteItem(item) }()
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
	if err != nil {
		t.Fatal(err)
	}
	if passwordAfter != nil {
		t.Fatal("Shouldn't have password")
	}
}

func TestAddingAndQueryingNewKeychain(t *testing.T) {
	keychainPath := tempPath(t)
	defer func() { _ = os.Remove(keychainPath) }()

	service, account, label, accessGroup, password := "TestAddingAndQueryingNewKeychain", "test", "", "", "toomanysecrets"

	k, err := keychain.NewKeychain(keychainPath, "my password")
	if err != nil {
		t.Fatal(err)
	}

	item := keychain.NewGenericPassword(service, account, label, []byte(password), accessGroup)
	item.UseKeychain(k)
	if err = keychain.AddItem(item); err != nil {
		t.Fatal(err)
	}

	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetMatchSearchList(k)
	query.SetService(service)
	query.SetAccount(account)
	query.SetLabel(label)
	query.SetAccessGroup(accessGroup)
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)

	results, err := keychain.QueryItem(query)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	} else if string(results[0].Data) != password {
		t.Fatalf("Expected password to be %s, got %s", password, results[0].Data)
	}

	// Search default keychain to make sure it's not there
	queryDefault := keychain.NewItem()
	queryDefault.SetSecClass(keychain.SecClassGenericPassword)
	queryDefault.SetService(service)
	queryDefault.SetMatchLimit(keychain.MatchLimitOne)
	queryDefault.SetReturnData(true)
	resultsDefault, err := keychain.QueryItem(queryDefault)
	if err != nil {
		t.Fatal(err)
	}
	if len(resultsDefault) != 0 {
		t.Fatalf("Expected no results")
	}
}

func tempPath(t *testing.T) string {
	temp, err := keychain.RandomID("go-keychain-test-")
	if err != nil {
		panic(err)
	}
	return filepath.Join(os.TempDir(), temp+".keychain")
}
