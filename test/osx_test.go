// +build darwin,!ios

package test

import (
	"io/ioutil"
	"os"
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

func TestAddingAndQueryingNewKeychain(t *testing.T) {
	file := tmpKeychain(t)
	defer os.Remove(file)

	service, account, label, accessGroup, password := "TestAddingAndQueryingNewKeychain", "test", "", "", "toomanysecrets"

	k, err := keychain.NewKeychain(file, "my password", false)
	if err != nil {
		t.Fatal(err)
	}

	item := keychain.NewGenericPassword(service, account, label, []byte(password), accessGroup)

	// add to the default keychain
	if err = keychain.AddItem(item); err != nil {
		t.Fatal(err)
	}

	defer keychain.DeleteGenericPasswordItem(service, account)

	item.UseKeychain(k)

	// and then to the new keychain
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
}

func tmpKeychain(t *testing.T) (path string) {
	file, err := ioutil.TempFile(os.TempDir(), "go-keychain-test")
	if err != nil {
		t.Fatal(err)
		return
	}
	os.Remove(file.Name())
	return file.Name() + ".keychain"
}
