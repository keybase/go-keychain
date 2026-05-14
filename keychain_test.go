//go:build darwin && !ios

package keychain

import (
	"testing"
)

func TestUseDataProtectionKeychainKey(t *testing.T) {
	if !dataProtectionKeychainAvailable() {
		// On macOS < 10.15 the key is intentionally empty (see macos.go).
		if UseDataProtectionKeychainKey != "" {
			t.Fatalf("expected empty key on macOS < 10.15, got %q", UseDataProtectionKeychainKey)
		}
		t.Skip("kSecUseDataProtectionKeychain unavailable (macOS < 10.15)")
	}

	// On macOS 10.15+ the kSecUseDataProtectionKeychain binding must resolve to
	// a non-empty key. An empty key here would mean the cgo binding or the
	// __builtin_available guard in macos.go is broken.
	if UseDataProtectionKeychainKey == "" {
		t.Fatal("UseDataProtectionKeychainKey is empty on macOS 10.15+; kSecUseDataProtectionKeychain binding failed")
	}
}

func TestSetUseDataProtectionKeychain(t *testing.T) {
	if UseDataProtectionKeychainKey == "" {
		t.Skip("kSecUseDataProtectionKeychain unavailable (macOS < 10.15)")
	}

	item := NewItem()
	if _, ok := item.attr[UseDataProtectionKeychainKey]; ok {
		t.Fatal("expected no data protection attribute on a fresh item")
	}

	item.SetUseDataProtectionKeychain(true)
	v, ok := item.attr[UseDataProtectionKeychainKey]
	if !ok {
		t.Fatal("expected data protection attribute to be set")
	}
	if v != true {
		t.Fatalf("expected attribute value true, got %v", v)
	}

	item.SetUseDataProtectionKeychain(false)
	v, ok = item.attr[UseDataProtectionKeychainKey]
	if !ok {
		t.Fatal("expected data protection attribute to remain set when false")
	}
	if v != false {
		t.Fatalf("expected attribute value false, got %v", v)
	}
}

func TestUseDataProtectionKeychainConvertsToCFDictionary(t *testing.T) {
	if UseDataProtectionKeychainKey == "" {
		t.Skip("kSecUseDataProtectionKeychain unavailable (macOS < 10.15)")
	}

	item := NewItem()
	item.SetSecClass(SecClassGenericPassword)
	item.SetService("TestUseDataProtectionKeychain")
	item.SetAccount("test")
	item.SetUseDataProtectionKeychain(true)

	// Exercises the bool -> CFBoolean marshalling path for the new key
	// without touching the real keychain.
	cfDict, err := ConvertMapToCFDictionary(item.attr)
	if err != nil {
		t.Fatalf("ConvertMapToCFDictionary failed: %v", err)
	}
	releaseCFDictionary(cfDict)
}
