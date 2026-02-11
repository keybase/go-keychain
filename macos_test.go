//go:build darwin && !ios
// +build darwin,!ios

package keychain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestSetAccessControl(t *testing.T) {
	item := NewItem()
	item.SetSecClass(SecClassGenericPassword)
	item.SetService("TestAccessControl")
	item.SetAccount("test-access-control")
	item.SetLabel("TestSetAccessControl")
	item.SetData([]byte("secret"))

	// SetAccessControl should succeed with valid accessible + flags.
	err := item.SetAccessControl(AccessibleWhenPasscodeSetThisDeviceOnly, AccessControlDevicePasscode)
	require.NoError(t, err)

	// kSecAttrAccessible should have been removed (mutually exclusive with kSecAttrAccessControl).
	_, hasAccessible := item.attr[AccessibleKey]
	assert.False(t, hasAccessible, "kSecAttrAccessible should be removed when kSecAttrAccessControl is set")

	// kSecAttrAccessControl should be set.
	_, hasAccessControl := item.attr[AccessControlKey]
	assert.True(t, hasAccessControl, "kSecAttrAccessControl should be set")
}

func TestSetAccessControlRemovesAccessible(t *testing.T) {
	item := NewItem()
	item.SetSecClass(SecClassGenericPassword)

	// First set accessible.
	item.SetAccessible(AccessibleWhenUnlocked)
	_, hasAccessible := item.attr[AccessibleKey]
	assert.True(t, hasAccessible, "kSecAttrAccessible should be set after SetAccessible")

	// Now set access control, which should remove accessible.
	err := item.SetAccessControl(AccessibleWhenPasscodeSetThisDeviceOnly, AccessControlDevicePasscode)
	require.NoError(t, err)

	_, hasAccessible = item.attr[AccessibleKey]
	assert.False(t, hasAccessible, "kSecAttrAccessible should be removed after SetAccessControl")
}

func TestSetAccessControlInvalidAccessible(t *testing.T) {
	item := NewItem()
	err := item.SetAccessControl(Accessible(999), AccessControlDevicePasscode)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid accessible value")
}

func TestSetUseDataProtectionKeychain(t *testing.T) {
	item := NewItem()
	item.SetUseDataProtectionKeychain(true)
	val, ok := item.attr[UseDataProtectionKeychainKey]
	assert.True(t, ok)
	assert.Equal(t, true, val)

	item.SetUseDataProtectionKeychain(false)
	val, ok = item.attr[UseDataProtectionKeychainKey]
	assert.True(t, ok)
	assert.Equal(t, false, val)
}

func TestAccessControlAddDeleteItem(t *testing.T) {
	item := NewItem()
	item.SetSecClass(SecClassGenericPassword)
	item.SetService("TestAccessControlAddDelete")
	item.SetAccount("test-ac-add-delete")
	item.SetLabel("TestAccessControlAddDeleteItem")
	item.SetData([]byte("biometry-secret"))
	item.SetSynchronizable(SynchronizableNo)
	item.SetUseDataProtectionKeychain(true)

	err := item.SetAccessControl(AccessibleWhenPasscodeSetThisDeviceOnly, AccessControlDevicePasscode)
	require.NoError(t, err)

	defer func() {
		dq := NewItem()
		dq.SetSecClass(SecClassGenericPassword)
		dq.SetService("TestAccessControlAddDelete")
		dq.SetAccount("test-ac-add-delete")
		dq.SetUseDataProtectionKeychain(true)
		_ = DeleteItem(dq)
	}()

	err = AddItem(item)
	if err != nil {
		// -34018 (errSecMissingEntitlement) occurs when the test binary is not
		// code-signed with keychain-access-groups entitlement, which is required
		// for the data protection keychain. Skip in that case.
		if err == Error(-34018) {
			t.Skip("skipping: test binary not code-signed with keychain entitlements (errSecMissingEntitlement)")
		}
		t.Fatal(err)
	}

	// Query it back.
	query := NewItem()
	query.SetSecClass(SecClassGenericPassword)
	query.SetService("TestAccessControlAddDelete")
	query.SetAccount("test-ac-add-delete")
	query.SetMatchLimit(MatchLimitOne)
	query.SetReturnData(true)
	query.SetUseDataProtectionKeychain(true)

	results, err := QueryItem(query)
	if err != nil {
		t.Fatal(err)
	}

	require.Len(t, results, 1)
	assert.Equal(t, []byte("biometry-secret"), results[0].Data)
}

func TestAccessControlFlagConstants(t *testing.T) {
	// Verify that flag constants are non-zero (they are bitmask flags).
	assert.NotZero(t, AccessControlUserPresence, "AccessControlUserPresence should be non-zero")
	assert.NotZero(t, AccessControlBiometryAny, "AccessControlBiometryAny should be non-zero")
	assert.NotZero(t, AccessControlBiometryCurrentSet, "AccessControlBiometryCurrentSet should be non-zero")
	assert.NotZero(t, AccessControlDevicePasscode, "AccessControlDevicePasscode should be non-zero")
	assert.NotZero(t, AccessControlOr, "AccessControlOr should be non-zero")
	assert.NotZero(t, AccessControlAnd, "AccessControlAnd should be non-zero")
	assert.NotZero(t, AccessControlPrivateKeyUsage, "AccessControlPrivateKeyUsage should be non-zero")
	assert.NotZero(t, AccessControlApplicationPassword, "AccessControlApplicationPassword should be non-zero")
}
