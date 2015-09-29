# Go Keychain

A library for accessing the Keychain for OSX and iOS.

Requires Mac OSX 9 or greater and iOS 7 or greater.

**WARNING**: This is still being tested and reviewed.

## Usage

```go
// Create generic password item with service, account, label, password, access group
item := keychain.NewGenericPassword("MyService", "gabriel", "A label", []byte("toomanysecrets"), "A123456789.group.com.mycorp")
item.SetSynchronizable(keychain.SynchronizableNo)
item.SetAccessible(keychain.AccessibleWhenUnlocked)
err := keychain.AddItem(item)
if err == keychain.ErrorDuplicateItem {
  // Duplicate
}

accounts, err := keychain.GetAccountsForService("MyService")
// Should have 1 account == "gabriel"

err := keychain.DeleteGenericPasswordItem("MyService", "gabriel")
if err == keychain.ErrorNotFound {
  // Not found
}
```


## iOS

Bindable package in `bind`. iOS project in `ios`. Run that project to test iOS.

To re-generate framework:

```
gomobile bind -target=ios -o ios/bind.framework github.com/keybase/go-keychain/bind
```
