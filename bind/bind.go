// +build darwin ios

package bind

import (
	"fmt"
	"reflect"

	"github.com/keybase/go-keychain"
)

func AddGenericPassword(service string, account string, label string, accessGroup string, password string) error {
	item := keychain.NewGenericPassword(service, account, label, []byte(password), accessGroup)
	return keychain.AddItem(item)
}

func DeleteGenericPassword(service string, account string, label string, accessGroup string) error {
	item := keychain.NewGenericPassword(service, account, label, nil, accessGroup)
	return keychain.DeleteItem(item)
}

// TestGenericPassword runs test code for generic password keychain item.
// This is here so we can export using gomobile bind and run this method on iOS simulator and device.
// Access groups aren't supported in iOS simulator.
func TestGenericPassword(service string, accessGroup string) error {
	var err error

	account := "Testing account with unicode テスト"
	item := keychain.NewGenericPassword(service, account, "", []byte("toomanysecrets"), accessGroup)

	account2 := "Testing account #2"
	item2 := keychain.NewGenericPassword(service, account2, "", []byte("toomanysecrets2"), accessGroup)

	// Cleanup
	keychain.DeleteItem(item)
	defer keychain.DeleteItem(item)
	keychain.DeleteItem(item2)
	defer keychain.DeleteItem(item2)

	// Test account names empty
	accounts, err := keychain.GetAccounts(service)
	if len(accounts) != 0 {
		return fmt.Errorf("Should have no accounts yet")
	}

	// Test add
	err = keychain.AddItem(item)
	if err != nil {
		return err
	}

	// Test dupe
	err = keychain.AddItem(item)
	if err != keychain.KeychainErrorDuplicateItem {
		return fmt.Errorf("Should error with duplicate item")
	}

	// Test add another
	err = keychain.AddItem(item2)
	if err != nil {
		return err
	}

	// Test querying attributes
	query := keychain.NewGenericPasswordQuery(service, account, "", accessGroup, keychain.MatchLimitAll, keychain.ReturnAttributes)
	results, err := keychain.QueryItem(query)
	if err != nil {
		return err
	}

	if len(results) != 1 {
		return fmt.Errorf("Invalid results count: %d", len(results))
	}

	if results[0].Service != service {
		return fmt.Errorf("Invalid service, %v != %v, %v", results[0].Service, service, results)
	}

	if results[0].Account != account {
		return fmt.Errorf("Invalid account, %v != %v, %v", results[0].Account, account, results)
	}

	if len(results[0].Data) != 0 {
		return fmt.Errorf("Password shouldn't come back when returning attributes")
	}

	// Test querying data
	password, err := keychain.GetGenericPassword(service, account, "", accessGroup)
	if err != nil {
		return err
	}

	if string(password) != "toomanysecrets" {
		return fmt.Errorf("Invalid password")
	}

	// Test account names
	accounts2, err := keychain.GetAccounts(service)
	if err != nil {
		return err
	}
	if len(accounts2) != 2 {
		return fmt.Errorf("Should have 2 accounts: %v", accounts2)
	}

	if !reflect.DeepEqual(accounts2, []string{account, account2}) {
		return fmt.Errorf("Invalid accounts: %v", accounts2)
	}

	// Remove
	queryDel := keychain.NewGenericPasswordQuery(service, account, "", accessGroup, keychain.MatchLimitAll, keychain.ReturnDefault)
	err = keychain.DeleteItem(queryDel)
	if err != nil {
		return err
	}

	// Test removed
	query3 := keychain.NewGenericPasswordQuery(service, account, "", accessGroup, keychain.MatchLimitAll, keychain.ReturnAttributes)
	results3, err := keychain.QueryItem(query3)

	if len(results3) != 0 {
		return fmt.Errorf("Results should have been empty")
	}

	accounts3, err := keychain.GetAccounts(service)
	if err != nil {
		return err
	}
	if len(accounts3) != 1 {
		return fmt.Errorf("Should have an account")
	}

	// Test remove not found
	err = keychain.DeleteItem(item)
	if err != keychain.KeychainErrorItemNotFound {
		return fmt.Errorf("Error should be not found")
	}

	return nil
}
