// +build darwin ios

package keychain

import (
	"reflect"
	"testing"
)

func TestGenericPassword(t *testing.T) {
	var err error

	service := "Testing service as unicode テスト"
	account := "Testing account with unicode テスト"
	item := NewGenericPassword(service, account, []byte("toomanysecrets"), "keybase", SynchronizableNo, AccessibleWhenUnlockedThisDeviceOnly)

	account2 := "Testing account #2"
	item2 := NewGenericPassword(service, account2, []byte("toomanysecrets2"), "keybase", SynchronizableNo, AccessibleWhenUnlockedThisDeviceOnly)

	// Cleanup
	DeleteItem(item)
	defer DeleteItem(item)
	DeleteItem(item2)
	defer DeleteItem(item2)

	// Test account names empty
	accounts, err := GetAccounts(service)
	if len(accounts) != 0 {
		t.Fatalf("Should have no accounts yet")
	}

	// Test add
	err = AddItem(item)
	if err != nil {
		t.Fatal(err)
	}

	// Test dupe
	err = AddItem(item)
	if err != KeychainErrorDuplicateItem {
		t.Fatal("Should error with duplicate item")
	}

	// Test add another
	err = AddItem(item2)
	if err != nil {
		t.Fatal(err)
	}

	// Test querying attributes
	query := NewGenericPasswordQuery(service, account, MatchLimitAll, ReturnAttributes)
	results, err := QueryItem(query)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 1 {
		t.Fatalf("Invalid results count: %d", len(results))
	}

	if results[0].Service != service {
		t.Fatalf("Invalid service")
	}

	if results[0].Account != account {
		t.Fatalf("Invalid account")
	}

	if len(results[0].Data) != 0 {
		t.Fatalf("Password shouldn't come back when returning attributes")
	}

	// Test querying data
	password, err := GetGenericPassword(service, account)
	if err != nil {
		t.Fatal(err)
	}

	if string(password) != "toomanysecrets" {
		t.Fatalf("Invalid password")
	}

	// Test account names
	accounts2, err := GetAccounts(service)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts2) != 2 {
		t.Fatalf("Should have 2 accounts: %v", accounts2)
	}

	if !reflect.DeepEqual(accounts2, []string{account, account2}) {
		t.Fatalf("Invalid accounts: %v", accounts2)
	}

	// Remove
	queryDel := NewGenericPasswordQuery(service, account, MatchLimitAll, ReturnDefault)
	err = DeleteItem(queryDel)
	if err != nil {
		t.Fatal(err)
	}

	// Test removed
	query3 := NewGenericPasswordQuery(service, account, MatchLimitAll, ReturnAttributes)
	results3, err := QueryItem(query3)

	if len(results3) != 0 {
		t.Fatalf("Results should have been empty")
	}

	accounts3, err := GetAccounts(service)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts3) != 1 {
		t.Fatalf("Should have an account")
	}

	// Test remove not found
	err = DeleteItem(item)
	if err != KeychainErrorItemNotFound {
		t.Fatal("Error should be not found")
	}
}
