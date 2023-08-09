//go:build darwin
// +build darwin

package keychain

// See https://developer.apple.com/library/ios/documentation/Security/Reference/keychainservices/index.html for the APIs used below.

// Also see https://developer.apple.com/library/ios/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html .

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"log"
	"runtime"
	"time"
	"unsafe"
)

// Error defines keychain errors
type Error int

var (
	// ErrorUnimplemented corresponds to errSecUnimplemented result code
	ErrorUnimplemented = Error(C.errSecUnimplemented)
	// ErrorParam corresponds to errSecParam result code
	ErrorParam = Error(C.errSecParam)
	// ErrorAllocate corresponds to errSecAllocate result code
	ErrorAllocate = Error(C.errSecAllocate)
	// ErrorNotAvailable corresponds to errSecNotAvailable result code
	ErrorNotAvailable = Error(C.errSecNotAvailable)
	// ErrorAuthFailed corresponds to errSecAuthFailed result code
	ErrorAuthFailed = Error(C.errSecAuthFailed)
	// ErrorDuplicateItem corresponds to errSecDuplicateItem result code
	ErrorDuplicateItem = Error(C.errSecDuplicateItem)
	// ErrorItemNotFound corresponds to errSecItemNotFound result code
	ErrorItemNotFound = Error(C.errSecItemNotFound)
	// ErrorInteractionNotAllowed corresponds to errSecInteractionNotAllowed result code
	ErrorInteractionNotAllowed = Error(C.errSecInteractionNotAllowed)
	// ErrorDecode corresponds to errSecDecode result code
	ErrorDecode = Error(C.errSecDecode)
	// ErrorNoSuchKeychain corresponds to errSecNoSuchKeychain result code
	ErrorNoSuchKeychain = Error(C.errSecNoSuchKeychain)
	// ErrorNoAccessForItem corresponds to errSecNoAccessForItem result code
	ErrorNoAccessForItem = Error(C.errSecNoAccessForItem)
	// ErrorReadOnly corresponds to errSecReadOnly result code
	ErrorReadOnly = Error(C.errSecReadOnly)
	// ErrorInvalidKeychain corresponds to errSecInvalidKeychain result code
	ErrorInvalidKeychain = Error(C.errSecInvalidKeychain)
	// ErrorDuplicateKeyChain corresponds to errSecDuplicateKeychain result code
	ErrorDuplicateKeyChain = Error(C.errSecDuplicateKeychain)
	// ErrorWrongVersion corresponds to errSecWrongSecVersion result code
	ErrorWrongVersion = Error(C.errSecWrongSecVersion)
	// ErrorReadonlyAttribute corresponds to errSecReadOnlyAttr result code
	ErrorReadonlyAttribute = Error(C.errSecReadOnlyAttr)
	// ErrorInvalidSearchRef corresponds to errSecInvalidSearchRef result code
	ErrorInvalidSearchRef = Error(C.errSecInvalidSearchRef)
	// ErrorInvalidItemRef corresponds to errSecInvalidItemRef result code
	ErrorInvalidItemRef = Error(C.errSecInvalidItemRef)
	// ErrorDataNotAvailable corresponds to errSecDataNotAvailable result code
	ErrorDataNotAvailable = Error(C.errSecDataNotAvailable)
	// ErrorDataNotModifiable corresponds to errSecDataNotModifiable result code
	ErrorDataNotModifiable = Error(C.errSecDataNotModifiable)
	// ErrorInvalidOwnerEdit corresponds to errSecInvalidOwnerEdit result code
	ErrorInvalidOwnerEdit = Error(C.errSecInvalidOwnerEdit)
	// ErrorUserCanceled corresponds to errSecUserCanceled result code
	ErrorUserCanceled = Error(C.errSecUserCanceled)
)

func checkError(errCode C.OSStatus) error {
	if errCode == C.errSecSuccess {
		return nil
	}
	return Error(errCode)
}

func (k Error) Error() (msg string) {
	// SecCopyErrorMessageString is only available on OSX, so derive manually.
	// Messages derived from `$ security error $errcode`.
	switch k {
	case ErrorUnimplemented:
		msg = "Function or operation not implemented."
	case ErrorParam:
		msg = "One or more parameters passed to the function were not valid."
	case ErrorAllocate:
		msg = "Failed to allocate memory."
	case ErrorNotAvailable:
		msg = "No keychain is available. You may need to restart your computer."
	case ErrorAuthFailed:
		msg = "The user name or passphrase you entered is not correct."
	case ErrorDuplicateItem:
		msg = "The specified item already exists in the keychain."
	case ErrorItemNotFound:
		msg = "The specified item could not be found in the keychain."
	case ErrorInteractionNotAllowed:
		msg = "User interaction is not allowed."
	case ErrorDecode:
		msg = "Unable to decode the provided data."
	case ErrorNoSuchKeychain:
		msg = "The specified keychain could not be found."
	case ErrorNoAccessForItem:
		msg = "The specified item has no access control."
	case ErrorReadOnly:
		msg = "Read-only error."
	case ErrorReadonlyAttribute:
		msg = "The attribute is read-only."
	case ErrorInvalidKeychain:
		msg = "The keychain is not valid."
	case ErrorDuplicateKeyChain:
		msg = "A keychain with the same name already exists."
	case ErrorWrongVersion:
		msg = "The version is incorrect."
	case ErrorInvalidItemRef:
		msg = "The item reference is invalid."
	case ErrorInvalidSearchRef:
		msg = "The search reference is invalid."
	case ErrorDataNotAvailable:
		msg = "The data is not available."
	case ErrorDataNotModifiable:
		msg = "The data is not modifiable."
	case ErrorInvalidOwnerEdit:
		msg = "An invalid attempt to change the owner of an item."
	case ErrorUserCanceled:
		msg = "User canceled the operation."
	default:
		msg = "Keychain Error."
	}
	return fmt.Sprintf("%s (%d)", msg, k)
}

// SecClass is the items class code
type SecClass int

// Keychain Item Classes
var (
	/*
		kSecClassGenericPassword item attributes:
		 kSecAttrAccess (OS X only)
		 kSecAttrAccessGroup (iOS; also OS X if kSecAttrSynchronizable specified)
		 kSecAttrAccessible (iOS; also OS X if kSecAttrSynchronizable specified)
		 kSecAttrAccount
		 kSecAttrService
	*/
	SecClassGenericPassword  SecClass = 1
	SecClassInternetPassword SecClass = 2
	SecClassCertificate      SecClass = 3
	SecClassIdentity         SecClass = 4
	SecClassCryptoKey        SecClass = 5
)

// SecClassKey is the key type for SecClass
var SecClassKey = attrKey(C.CFTypeRef(C.kSecClass))
var secClassTypeRef = map[SecClass]C.CFTypeRef{
	SecClassGenericPassword:  C.CFTypeRef(C.kSecClassGenericPassword),
	SecClassInternetPassword: C.CFTypeRef(C.kSecClassInternetPassword),
	SecClassIdentity:         C.CFTypeRef(C.kSecClassIdentity),
}

var SecKeyTypeKey = attrKey(C.CFTypeRef(C.kSecAttrKeyType))

var (
	KeyTypeRSA              = CFStringToString(C.kSecAttrKeyTypeRSA)
	KeyTypeDSA              = CFStringToString(C.kSecAttrKeyTypeDSA)
	KeyTypeAES              = CFStringToString(C.kSecAttrKeyTypeAES)
	KeyTypeDES              = CFStringToString(C.kSecAttrKeyTypeDES)
	KeyType3DES             = CFStringToString(C.kSecAttrKeyType3DES)
	KeyTypeRC4              = CFStringToString(C.kSecAttrKeyTypeRC4)
	KeyTypeRC2              = CFStringToString(C.kSecAttrKeyTypeRC2)
	KeyTypeCAST             = CFStringToString(C.kSecAttrKeyTypeCAST)
	KeyTypeECDSA            = CFStringToString(C.kSecAttrKeyTypeECDSA)
	KeyTypeECSECPrimeRandom = CFStringToString(C.kSecAttrKeyTypeECSECPrimeRandom)
	// Add other key types as needed
)

var keyTypeEnumToString = map[string]string{
	KeyTypeRSA:              "RSA",
	KeyTypeDSA:              "DSA",
	KeyTypeAES:              "AES",
	KeyTypeDES:              "DES",
	KeyType3DES:             "3DES",
	KeyTypeRC4:              "RC4",
	KeyTypeRC2:              "RC2",
	KeyTypeCAST:             "CAST",
	KeyTypeECDSA:            "ECDSA",
	KeyTypeECSECPrimeRandom: "ECSECPrimeRandom",
	// Add other key types as needed
}

// SecKeyAlgorithm is a type representing the key algorithms.
type SecKeyAlgorithm string

const (
	// RSA algorithms
	RSAEncryptionPKCS1               SecKeyAlgorithm = "rsaEncryptionPKCS1"
	RSASignatureDigestPKCS1v15SHA1   SecKeyAlgorithm = "rsaSignatureDigestPKCS1v15SHA1"
	RSASignatureDigestPKCS1v15SHA256 SecKeyAlgorithm = "rsaSignatureDigestPKCS1v15SHA256"
	RSASignatureDigestPKCS1v15SHA384 SecKeyAlgorithm = "rsaSignatureDigestPKCS1v15SHA384"
	RSASignatureDigestPKCS1v15SHA512 SecKeyAlgorithm = "rsaSignatureDigestPKCS1v15SHA512"
	RSASignatureDigestPSSSHA256      SecKeyAlgorithm = "rsaSignatureDigestPSSSHA256"
	RSASignatureDigestPSSSHA384      SecKeyAlgorithm = "rsaSignatureDigestPSSSHA384"
	RSASignatureDigestPSSSHA512      SecKeyAlgorithm = "rsaSignatureDigestPSSSHA512"
	// ECDSA algorithms
	ECDSASignatureDigestX962SHA1   SecKeyAlgorithm = "ecdsaSignatureDigestX962SHA1"
	ECDSASignatureDigestX962SHA256 SecKeyAlgorithm = "ecdsaSignatureDigestX962SHA256"
	ECDSASignatureDigestX962SHA384 SecKeyAlgorithm = "ecdsaSignatureDigestX962SHA384"
	ECDSASignatureDigestX962SHA512 SecKeyAlgorithm = "ecdsaSignatureDigestX962SHA512"
	// ... add other constants as needed
)

var secKeyAlgorithmMap = map[SecKeyAlgorithm]C.SecKeyAlgorithm{
	// RSA algorithms
	RSAEncryptionPKCS1:               C.kSecKeyAlgorithmRSAEncryptionPKCS1,
	RSASignatureDigestPKCS1v15SHA1:   C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1,
	RSASignatureDigestPKCS1v15SHA256: C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256,
	RSASignatureDigestPKCS1v15SHA384: C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384,
	RSASignatureDigestPKCS1v15SHA512: C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512,
	RSASignatureDigestPSSSHA256:      C.kSecKeyAlgorithmRSASignatureDigestPSSSHA256,
	RSASignatureDigestPSSSHA384:      C.kSecKeyAlgorithmRSASignatureDigestPSSSHA384,
	RSASignatureDigestPSSSHA512:      C.kSecKeyAlgorithmRSASignatureDigestPSSSHA512,
	// ECDSA algorithms
	ECDSASignatureDigestX962SHA1:   C.kSecKeyAlgorithmECDSASignatureDigestX962SHA1,
	ECDSASignatureDigestX962SHA256: C.kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
	ECDSASignatureDigestX962SHA384: C.kSecKeyAlgorithmECDSASignatureDigestX962SHA384,
	ECDSASignatureDigestX962SHA512: C.kSecKeyAlgorithmECDSASignatureDigestX962SHA512,
	// ... add other mappings as needed
}

var (
	// PersistentRefKey is for kSecValuePersistentRef
	PersistentRefKey = attrKey(C.CFTypeRef(C.kSecValuePersistentRef))
	// RefKey is for kSecValueRef
	RefKey = attrKey(C.CFTypeRef(C.kSecValueRef))
	// ValueRef is for kSecValueRef
	ValueRef = attrKey(C.CFTypeRef(C.kSecValueRef))

	// ServiceKey is for kSecAttrService
	ServiceKey = attrKey(C.CFTypeRef(C.kSecAttrService))

	// ServerKey is for kSecAttrServer
	ServerKey = attrKey(C.CFTypeRef(C.kSecAttrServer))
	// ProtocolKey is for kSecAttrProtocol
	ProtocolKey = attrKey(C.CFTypeRef(C.kSecAttrProtocol))
	// AuthenticationTypeKey is for kSecAttrAuthenticationType
	AuthenticationTypeKey = attrKey(C.CFTypeRef(C.kSecAttrAuthenticationType))
	// PortKey is for kSecAttrPort
	PortKey = attrKey(C.CFTypeRef(C.kSecAttrPort))
	// PathKey is for kSecAttrPath
	PathKey = attrKey(C.CFTypeRef(C.kSecAttrPath))

	// LabelKey is for kSecAttrLabel
	LabelKey = attrKey(C.CFTypeRef(C.kSecAttrLabel))
	// AccountKey is for kSecAttrAccount
	AccountKey = attrKey(C.CFTypeRef(C.kSecAttrAccount))
	// AccessGroupKey is for kSecAttrAccessGroup
	AccessGroupKey = attrKey(C.CFTypeRef(C.kSecAttrAccessGroup))
	// DataKey is for kSecValueData
	DataKey = attrKey(C.CFTypeRef(C.kSecValueData))
	// DescriptionKey is for kSecAttrDescription
	DescriptionKey = attrKey(C.CFTypeRef(C.kSecAttrDescription))
	// CommentKey is for kSecAttrComment
	CommentKey = attrKey(C.CFTypeRef(C.kSecAttrComment))
	// CreationDateKey is for kSecAttrCreationDate
	CreationDateKey = attrKey(C.CFTypeRef(C.kSecAttrCreationDate))
	// ModificationDateKey is for kSecAttrModificationDate
	ModificationDateKey = attrKey(C.CFTypeRef(C.kSecAttrModificationDate))

	TokenIDKey = attrKey(C.CFTypeRef(C.kSecAttrTokenID))
	// KeySizeInBitsKey is for kSecAttrKeySizeInBits
	KeySizeInBitsKey = attrKey(C.CFTypeRef(C.kSecAttrKeySizeInBits))
	// PrivateKeyAttrsKey is for kSecPrivateKeyAttrs
	PrivateKeyAttrsKey = attrKey(C.CFTypeRef(C.kSecPrivateKeyAttrs))
)

// Synchronizable is the items synchronizable status
type Synchronizable int

const (
	// SynchronizableDefault is the default setting
	SynchronizableDefault Synchronizable = 0
	// SynchronizableAny is for kSecAttrSynchronizableAny
	SynchronizableAny = 1
	// SynchronizableYes enables synchronization
	SynchronizableYes = 2
	// SynchronizableNo disables synchronization
	SynchronizableNo = 3
)

// SynchronizableKey is the key type for Synchronizable
var SynchronizableKey = attrKey(C.CFTypeRef(C.kSecAttrSynchronizable))
var syncTypeRef = map[Synchronizable]C.CFTypeRef{
	SynchronizableAny: C.CFTypeRef(C.kSecAttrSynchronizableAny),
	SynchronizableYes: C.CFTypeRef(C.kCFBooleanTrue),
	SynchronizableNo:  C.CFTypeRef(C.kCFBooleanFalse),
}

// Accessible is the items accessibility
type Accessible int

const (
	// AccessibleDefault is the default
	AccessibleDefault Accessible = 0
	// AccessibleWhenUnlocked is when unlocked
	AccessibleWhenUnlocked = 1
	// AccessibleAfterFirstUnlock is after first unlock
	AccessibleAfterFirstUnlock = 2
	// AccessibleAlways is always
	AccessibleAlways = 3
	// AccessibleWhenPasscodeSetThisDeviceOnly is when passcode is set
	AccessibleWhenPasscodeSetThisDeviceOnly = 4
	// AccessibleWhenUnlockedThisDeviceOnly is when unlocked for this device only
	AccessibleWhenUnlockedThisDeviceOnly = 5
	// AccessibleAfterFirstUnlockThisDeviceOnly is after first unlock for this device only
	AccessibleAfterFirstUnlockThisDeviceOnly = 6
	// AccessibleAccessibleAlwaysThisDeviceOnly is always for this device only
	AccessibleAccessibleAlwaysThisDeviceOnly = 7
)

// MatchLimit is whether to limit results on query
type MatchLimit int

const (
	// MatchLimitDefault is the default
	MatchLimitDefault MatchLimit = 0
	// MatchLimitOne limits to one result
	MatchLimitOne = 1
	// MatchLimitAll is no limit
	MatchLimitAll = 2
)

// MatchLimitKey is key type for MatchLimit
var MatchLimitKey = attrKey(C.CFTypeRef(C.kSecMatchLimit))
var matchTypeRef = map[MatchLimit]C.CFTypeRef{
	MatchLimitOne: C.CFTypeRef(C.kSecMatchLimitOne),
	MatchLimitAll: C.CFTypeRef(C.kSecMatchLimitAll),
}

// ReturnAttributesKey is key type for kSecReturnAttributes
var ReturnAttributesKey = attrKey(C.CFTypeRef(C.kSecReturnAttributes))

// ReturnDataKey is key type for kSecReturnData
var ReturnDataKey = attrKey(C.CFTypeRef(C.kSecReturnData))

// ReturnRefKey is key type for kSecReturnRef
var ReturnRefKey = attrKey(C.CFTypeRef(C.kSecReturnRef))

// ReturnPersistentRefKey is the key type for kSecReturnPersistentRef
var ReturnPersistentRefKey = attrKey(C.CFTypeRef(C.kSecReturnPersistentRef))

// Item for adding, querying or deleting.
type Item struct {
	// Values can be string, []byte, Convertable or CFTypeRef (constant).
	attr     map[string]interface{}
	secClass SecClass
}

// SetSecClass sets the security class
func (k *Item) SetSecClass(sc SecClass) {
	k.attr[SecClassKey] = secClassTypeRef[sc]
	k.secClass = sc
}

// SetValueRef sets a CFTypeRef as a value
func (k *Item) SetValueRef(secRef C.CFTypeRef) {
	k.attr[ValueRef] = secRef
}

// SetInt32 sets an int32 attribute for a string key
func (k *Item) SetInt32(key string, v int32) {
	if v != 0 {
		k.attr[key] = v
	} else {
		delete(k.attr, key)
	}
}

// SetString sets a string attribute for a string key
func (k *Item) SetString(key string, s string) {
	if s != "" {
		k.attr[key] = s
	} else {
		delete(k.attr, key)
	}
}

// SetService sets the service attribute (for generic application items)
func (k *Item) SetService(s string) {
	k.SetString(ServiceKey, s)
}

// SetServer sets the server attribute (for internet password items)
func (k *Item) SetServer(s string) {
	k.SetString(ServerKey, s)
}

// SetProtocol sets the protocol attribute (for internet password items)
// Example values are: "htps", "http", "smb "
func (k *Item) SetProtocol(s string) {
	k.SetString(ProtocolKey, s)
}

// SetAuthenticationType sets the authentication type attribute (for internet password items)
func (k *Item) SetAuthenticationType(s string) {
	k.SetString(AuthenticationTypeKey, s)
}

// SetPort sets the port attribute (for internet password items)
func (k *Item) SetPort(v int32) {
	k.SetInt32(PortKey, v)
}

// SetPath sets the path attribute (for internet password items)
func (k *Item) SetPath(s string) {
	k.SetString(PathKey, s)
}

// SetAccount sets the account attribute
func (k *Item) SetAccount(a string) {
	k.SetString(AccountKey, a)
}

// SetLabel sets the label attribute
func (k *Item) SetLabel(l string) {
	k.SetString(LabelKey, l)
}

// SetDescription sets the description attribute
func (k *Item) SetDescription(s string) {
	k.SetString(DescriptionKey, s)
}

// SetComment sets the comment attribute
func (k *Item) SetComment(s string) {
	k.SetString(CommentKey, s)
}

// SetData sets the data attribute
func (k *Item) SetData(b []byte) {
	if b != nil {
		k.attr[DataKey] = b
	} else {
		delete(k.attr, DataKey)
	}
}

// SetAccessGroup sets the access group attribute
func (k *Item) SetAccessGroup(ag string) {
	k.SetString(AccessGroupKey, ag)
}

// SetSynchronizable sets the synchronizable attribute
func (k *Item) SetSynchronizable(sync Synchronizable) {
	if sync != SynchronizableDefault {
		k.attr[SynchronizableKey] = syncTypeRef[sync]
	} else {
		delete(k.attr, SynchronizableKey)
	}
}

// SetAccessible sets the accessible attribute
func (k *Item) SetAccessible(accessible Accessible) {
	if accessible != AccessibleDefault {
		k.attr[AccessibleKey] = accessibleTypeRef[accessible]
	} else {
		delete(k.attr, AccessibleKey)
	}
}

// SetMatchLimit sets the match limit
func (k *Item) SetMatchLimit(matchLimit MatchLimit) {
	if matchLimit != MatchLimitDefault {
		k.attr[MatchLimitKey] = matchTypeRef[matchLimit]
	} else {
		delete(k.attr, MatchLimitKey)
	}
}

// SetReturnAttributes sets the return value type on query
// See: https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_return_result_keys
// and https://developer.apple.com/documentation/security/ksecreturnattributes
func (k *Item) SetReturnAttributes(b bool) {
	k.attr[ReturnAttributesKey] = b
}

// SetReturnData enables returning data on query
// See: https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_return_result_keys
// and https://developer.apple.com/documentation/security/ksecreturndata
func (k *Item) SetReturnData(b bool) {
	k.attr[ReturnDataKey] = b
}

// SetReturnRef enables returning references on query
// See: https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_return_result_keys
// and https://developer.apple.com/documentation/security/ksecvalueref
func (k *Item) SetReturnRef(b bool) {
	k.attr[ReturnRefKey] = b
}

// SetReturnPersistentRef enables returning persistent references on query.
// See: https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_return_result_keys
// and  https://developer.apple.com/documentation/security/ksecreturnpersistentref
func (k *Item) SetReturnPersistentRef(b bool) {
	k.attr[ReturnPersistentRefKey] = b
}

// SetPersistentRef sets the PersistentRefKey to the []byte slice representing a specific keychain item
// See:  https://developer.apple.com/documentation/security/ksecreturnpersistentref
func (k *Item) SetPersistentRef(b []byte) {
	if len(b) > 0 {
		k.attr[PersistentRefKey] = b
	} else {
		delete(k.attr, PersistentRefKey)
	}
}

// NewItem is a new empty keychain item
func NewItem() Item {
	return Item{make(map[string]interface{}), 0}
}

// NewGenericPassword creates a generic password item with the default keychain. This is a convenience method.
func NewGenericPassword(service string, account string, label string, data []byte, accessGroup string) Item {
	item := NewItem()
	item.SetSecClass(SecClassGenericPassword)
	item.SetService(service)
	item.SetAccount(account)
	item.SetLabel(label)
	item.SetData(data)
	item.SetAccessGroup(accessGroup)
	return item
}

// AddItem adds a Item to a Keychain
func AddItem(item Item) error {
	cfDict, err := ConvertMapToCFDictionary(item.attr)
	if err != nil {
		return err
	}
	defer Release(C.CFTypeRef(cfDict))

	errCode := C.SecItemAdd(cfDict, nil)
	err = checkError(errCode)
	return err
}

// UpdateItem updates the queryItem with the parameters from updateItem
func UpdateItem(queryItem Item, updateItem Item) error {
	cfDict, err := ConvertMapToCFDictionary(queryItem.attr)
	if err != nil {
		return err
	}
	defer Release(C.CFTypeRef(cfDict))
	cfDictUpdate, err := ConvertMapToCFDictionary(updateItem.attr)
	if err != nil {
		return err
	}
	defer Release(C.CFTypeRef(cfDictUpdate))
	errCode := C.SecItemUpdate(cfDict, cfDictUpdate)
	err = checkError(errCode)
	return err
}

// QueryResult stores all possible results from queries.
// Not all fields are applicable all the time. Results depend on query.
type QueryResult struct {
	// For all keychain items
	PersistentRef    []byte
	CreationDate     time.Time
	ModificationDate time.Time
	Comment          string

	// For generic application items
	Service string

	// For internet password items
	Server             string
	Protocol           string
	AuthenticationType string
	Port               int32
	Path               string

	Account     string
	AccessGroup string
	Label       string
	Description string
	Data        []byte

	// Certificates
	Certificate    *CertificateRef
	HasCertificate bool

	// Identity
	Identity    *IdentityRef
	HasIdentity bool
	TokenID     string

	// Keys
	Key     *KeyRef
	HasKey  bool
	KeyType string
}

// QueryItemRef returns query result as CFTypeRef. You must release it when you are done.
func QueryItemRef(item Item) (C.CFTypeRef, error) {
	cfDict, err := ConvertMapToCFDictionary(item.attr)
	if err != nil {
		return 0, err
	}
	defer Release(C.CFTypeRef(cfDict))

	var resultsRef C.CFTypeRef
	errCode := C.SecItemCopyMatching(cfDict, &resultsRef) //nolint
	if Error(errCode) == ErrorItemNotFound {
		return 0, nil
	}
	err = checkError(errCode)
	if err != nil {
		return 0, err
	}
	return resultsRef, nil
}

// QueryItem returns a list of query results.
// See: https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_return_result_keys
// for the results that can be returned.
func QueryItem(item Item) ([]QueryResult, error) {
	resultsRef, err := QueryItemRef(item)
	if err != nil {
		return nil, err
	}
	if resultsRef == 0 {
		return nil, nil
	}
	defer Release(resultsRef)

	results := make([]QueryResult, 0, 1)

	typeID := C.CFGetTypeID(resultsRef)
	if typeID == C.CFArrayGetTypeID() {
		arr := CFArrayToArray(C.CFArrayRef(resultsRef))
		for _, ref := range arr {
			elementTypeID := C.CFGetTypeID(ref)
			if elementTypeID == C.CFDictionaryGetTypeID() {
				item, err := convertResult(C.CFDictionaryRef(ref), item.secClass)
				if err != nil {
					return nil, err
				}
				results = append(results, *item)
			} else {
				return nil, fmt.Errorf("invalid result type (If you SetReturnRef(true) you should use QueryItemRef directly)")
			}
		}
	} else if typeID == C.CFDictionaryGetTypeID() {
		item, err := convertResult(C.CFDictionaryRef(resultsRef), item.secClass)
		if err != nil {
			return nil, err
		}
		results = append(results, *item)
	} else if typeID == C.CFDataGetTypeID() {
		b, err := CFDataToBytes(C.CFDataRef(resultsRef))
		if err != nil {
			return nil, err
		}
		item := QueryResult{Data: b}
		results = append(results, item)
	} else {
		return nil, fmt.Errorf("Invalid result type: %s", CFTypeDescription(resultsRef))
	}

	return results, nil
}

func attrKey(ref C.CFTypeRef) string {
	return CFStringToString(C.CFStringRef(ref))
}

func convertResult(d C.CFDictionaryRef, sc SecClass) (*QueryResult, error) {
	m := CFDictionaryToMap(d)
	result := QueryResult{}
	for k, v := range m {
		key := attrKey(k)
		switch key {
		case ServiceKey:
			result.Service = CFStringToString(C.CFStringRef(v))
		case ServerKey:
			result.Server = CFStringToString(C.CFStringRef(v))
		case ProtocolKey:
			result.Protocol = CFStringToString(C.CFStringRef(v))
		case AuthenticationTypeKey:
			result.AuthenticationType = CFStringToString(C.CFStringRef(v))
		case PortKey:
			val := CFNumberToInterface(C.CFNumberRef(v))
			result.Port = val.(int32)
		case PathKey:
			result.Path = CFStringToString(C.CFStringRef(v))
		case AccountKey:
			result.Account = CFStringToString(C.CFStringRef(v))
		case AccessGroupKey:
			result.AccessGroup = CFStringToString(C.CFStringRef(v))
		case LabelKey:
			result.Label = CFStringToString(C.CFStringRef(v))
		case DescriptionKey:
			result.Description = CFStringToString(C.CFStringRef(v))
		case CommentKey:
			result.Comment = CFStringToString(C.CFStringRef(v))
		case DataKey:
			b, err := CFDataToBytes(C.CFDataRef(v))
			if err != nil {
				return nil, err
			}
			result.Data = b
		case TokenIDKey:
			result.TokenID = CFStringToString(C.CFStringRef(v))
		case PersistentRefKey:
			b, err := CFDataToBytes(C.CFDataRef(v))
			if err != nil {
				return nil, err
			}
			result.PersistentRef = b
		case RefKey:
			switch sc {
			case SecClassCertificate:
				result.Certificate = newCertificateRef(v)
				result.HasCertificate = true
			case SecClassIdentity:
				result.Identity = newIdentityRef(v)
				result.HasIdentity = true
			case SecClassCryptoKey:
				result.Key = newKeyRef(v)
				result.HasKey = true
				// case SecClassGenericPassword:
				// case SecClassInternetPassword:
				// 	log.Println("Ref type for Passwords not supported.")
				// default:
				// 	log.Printf("Unhandled SecClass in conversion: %v\n", key)
			}
		case CreationDateKey:
			result.CreationDate = CFDateToTime(C.CFDateRef(v))
		case ModificationDateKey:
			result.ModificationDate = CFDateToTime(C.CFDateRef(v))
		case SecKeyTypeKey:
			enumStr := CFKeyTypeEnumToString(C.CFNumberRef(v))
			keyType, ok := keyTypeEnumToString[enumStr]
			if !ok {
				return nil, fmt.Errorf("unhandled key type in kSecAttrKeyType: %v", enumStr)
			} else {
				result.KeyType = keyType
			}
			// default:
			// 	log.Printf("Unhandled key in conversion: %v\n", key)
		}
	}
	return &result, nil
}

func newCertificateRef(v C.CFTypeRef) *CertificateRef {
	Retain(v)
	cert := &CertificateRef{C.SecCertificateRef(v)}
	runtime.SetFinalizer(cert, func(certRef *CertificateRef) {
		Release(C.CFTypeRef(certRef.cCertificateRef))
	})
	return cert
}

func newIdentityRef(v C.CFTypeRef) *IdentityRef {
	Retain(v)
	ident := &IdentityRef{C.SecIdentityRef(v)}
	runtime.SetFinalizer(ident, func(identRef *IdentityRef) {
		Release(C.CFTypeRef(identRef.cIdentityRef))
	})
	return ident
}

func newKeyRef(v C.CFTypeRef) *KeyRef {
	Retain(v)
	key := &KeyRef{C.SecKeyRef(v)}
	runtime.SetFinalizer(key, func(keyRef *KeyRef) {
		Release(C.CFTypeRef(keyRef.cKeyRef))
	})
	return key
}

// DeleteGenericPasswordItem removes a generic password item.
func DeleteGenericPasswordItem(service string, account string) error {
	item := NewItem()
	item.SetSecClass(SecClassGenericPassword)
	item.SetService(service)
	item.SetAccount(account)
	return DeleteItem(item)
}

// DeleteItem removes an Item
func DeleteItem(item Item) error {
	cfDict, err := ConvertMapToCFDictionary(item.attr)
	if err != nil {
		return err
	}
	defer Release(C.CFTypeRef(cfDict))

	errCode := C.SecItemDelete(cfDict)
	return checkError(errCode)
}

// GetAccountsForService is deprecated.
// Deprecated: use GetGenericPasswordAccounts instead.
func GetAccountsForService(service string) ([]string, error) {
	return GetGenericPasswordAccounts(service)
}

// GetGenericPasswordAccounts returns generic password accounts for service. This is a convenience method.
func GetGenericPasswordAccounts(service string) ([]string, error) {
	query := NewItem()
	query.SetSecClass(SecClassGenericPassword)
	query.SetService(service)
	query.SetMatchLimit(MatchLimitAll)
	query.SetReturnAttributes(true)
	results, err := QueryItem(query)
	if err != nil {
		return nil, err
	}

	accounts := make([]string, 0, len(results))
	for _, r := range results {
		accounts = append(accounts, r.Account)
	}

	return accounts, nil
}

// GetGenericPassword returns password data for service and account. This is a convenience method.
// If item is not found returns nil, nil.
func GetGenericPassword(service string, account string, label string, accessGroup string) ([]byte, error) {
	query := NewItem()
	query.SetSecClass(SecClassGenericPassword)
	query.SetService(service)
	query.SetAccount(account)
	query.SetLabel(label)
	query.SetAccessGroup(accessGroup)
	// https://developer.apple.com/documentation/security/1398306-secitemcopymatching
	// You can't combine the kSecReturnData and kSecMatchLimitAll options when copying password items.
	query.SetMatchLimit(MatchLimitOne)
	query.SetReturnData(true)
	results, err := QueryItem(query)
	if err != nil {
		return nil, err
	}
	if len(results) > 1 {
		return nil, fmt.Errorf("Too many results")
	}
	if len(results) == 1 {
		return results[0].Data, nil
	}
	return nil, nil
}

// Utility Refs for Certificate, Keys and Identities (which are both a Cert and a Key)

// CertificateRef for interacting with a specific keychain certificate
type CertificateRef struct {
	cCertificateRef C.SecCertificateRef
}

// GetCertificateData returns the certificate as a byte slice.
// See:https://developer.apple.com/documentation/security/1396080-seccertificatecopydata .
// The certificate object for which you wish to return the DER (Distinguished Encoding Rules) representation of the X.509 certificate.
func (c *CertificateRef) GetCertificateData() ([]byte, error) {
	cfData := C.SecCertificateCopyData(c.cCertificateRef)
	defer Release(C.CFTypeRef(cfData))
	return CFDataToBytes(cfData)
}

type TrustRef struct {
	cTrustRef C.SecTrustRef
}

func (c *CertificateRef) createTrustRef() (*TrustRef, error) {
	// See: https://developer.apple.com/documentation/security/1397202-secpolicycreatebasicx509
	basicPolicyRef := C.SecPolicyCreateBasicX509()

	var trustRef C.SecTrustRef
	// https://developer.apple.com/documentation/security/1401555-sectrustcreatewithcertificates
	//nolint:gocritic//dupSubExpr: suspicious identical LHS and RHS for `==` operator.
	errCode := C.SecTrustCreateWithCertificates(C.CFTypeRef(c.cCertificateRef), C.CFTypeRef(basicPolicyRef), &trustRef)
	err := checkError(errCode)
	if err != nil {
		return nil, fmt.Errorf("could not create SecTrust object for certificate: %w", err)
	}

	trust := &TrustRef{trustRef}
	runtime.SetFinalizer(trust, func(trustRef *TrustRef) {
		Release(C.CFTypeRef(trustRef.cTrustRef))
	})

	return trust, nil
}

// GetCertChainData returns a [][]byte containing the bytes of the certificate chain for the given cert.
// See: https://developer.apple.com/documentation/security/1396080-seccertificatecopydata  and https://developer.apple.com/documentation/security/3747134-sectrustcopycertificatechain
// The certificate object for which you wish to return the DER (Distinguished Encoding Rules) representation of the X.509 certificate.
func (c *CertificateRef) GetCertChainData() ([][]byte, error) {
	return c.getCertChainData(nil)
}

// GetCertChainDataWithAnchor returns a [][]byte containing the bytes of the certificate chain for the given cert.
// See: https://developer.apple.com/documentation/security/1396080-seccertificatecopydata  and https://developer.apple.com/documentation/security/3747134-sectrustcopycertificatechain
// The certificate object for which you wish to return the DER (Distinguished Encoding Rules) representation of the X.509 certificate.
func (c *CertificateRef) GetCertChainDataWithAnchor(anchor []*CertificateRef) ([][]byte, error) {
	return c.getCertChainData(anchor)
}

// SetTrustAnchorCertificates returns a [][]byte containing the bytes of the certificate chain for the given cert.
// See: https://developer.apple.com/documentation/security/1396098-sectrustsetanchorcertificates
// The certificate object for which you wish to return the DER (Distinguished Encoding Rules) representation of the X.509 certificate.
func (c *CertificateRef) SetTrustAnchorCertificates(trust *TrustRef, anchors C.CFMutableArrayRef) ([][]byte, error) {
	errCode := C.SecTrustSetAnchorCertificates(trust.cTrustRef, C.CFArrayRef(anchors))
	err := checkError(errCode)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

// getCertChainData returns a [][]byte containing the bytes of the certificate chain for the given cert.
// See:https://developer.apple.com/documentation/security/1396080-seccertificatecopydata  and https://developer.apple.com/documentation/security/3747134-sectrustcopycertificatechain
// The certificate object for which you wish to return the DER (Distinguished Encoding Rules) representation of the X.509 certificate.
func (c *CertificateRef) getCertChainData(anchorRefs []*CertificateRef) ([][]byte, error) {
	// Create the trust reference.
	trust, err := c.createTrustRef()
	if err != nil {
		return nil, err
	}

	// If they specified anchors, add them along with the existing trust anchors.
	if len(anchorRefs) > 0 {
		var cAnchors *MutableArrayRef

		// Get the currently trusted certs.
		cAnchors, err = TrustCopyAnchorCertificates()
		if err != nil {
			return nil, err
		}

		for _, anchor := range anchorRefs {
			if anchor == nil {
				continue
			}

			// append our cert to the arrayRef.
			cAnchors.Append(C.CFTypeRef(anchor.cCertificateRef))
		}

		_, err = c.SetTrustAnchorCertificates(trust, cAnchors.arrayRef)
		if err != nil {
			return nil, err
		}
	}

	var cfError C.CFErrorRef
	// https://developer.apple.com/documentation/security/2980705-sectrustevaluatewitherror
	//nolint:gocritic//dupSubExpr: suspicious identical LHS and RHS for `==` operator.
	resultBool := C.SecTrustEvaluateWithError(trust.cTrustRef, &cfError)

	if !bool(resultBool) {
		err = CFErrorError(cfError)
		if err != nil {
			return nil, fmt.Errorf("could not evaluate SecTrust object for certificate: %w", err)
		}
	}

	// Now you can use SecTrustGetCertificateCount and SecTrustGetCertificateAtIndex to get the certificates in the chain
	// https://developer.apple.com/documentation/security/3747134-sectrustcopycertificatechain
	chainRef := C.SecTrustCopyCertificateChain(trust.cTrustRef)
	certChainRefs := CFArrayToArray(chainRef)
	var certChain [][]byte
	for _, certRef := range certChainRefs {
		var (
			cr   *CertificateRef
			data []byte
		)

		cr = newCertificateRef(certRef)
		data, err = cr.GetCertificateData()
		if err != nil {
			return nil, err
		}

		certChain = append(certChain, data)
	}

	return certChain, nil
}

// KeyRef contains a reference to a keychain secure key and allows for signing operations
type KeyRef struct {
	cKeyRef C.SecKeyRef
}

// Sign creates the cryptographic signature for the digest using private key KeyRef and returns it as a byte slice
func (key *KeyRef) SignWithAlgorithm(digest []byte, algo SecKeyAlgorithm) ([]byte, error) {
	cfDigest, err := BytesToCFData(digest)
	defer Release(C.CFTypeRef(cfDigest))
	if err != nil {
		return nil, err
	}

	secKeyAlgo, ok := secKeyAlgorithmMap[algo]
	if !ok {
		return nil, fmt.Errorf("unsupported security algorithm: %v", algo)
	}

	// sign the digest
	var cErr C.CFErrorRef

	//nolint:gocritic//dupSubExpr: suspicious identical LHS and RHS for `==` operator.
	cSig := C.SecKeyCreateSignature(key.cKeyRef, secKeyAlgo, cfDigest, &cErr)
	if err := CFErrorError(cErr); err != nil {
		defer Release(C.CFTypeRef(cErr))
		return nil, err
	}

	//nolint:gocritic//dupSubExpr: suspicious identical LHS and RHS for `==` operator.
	defer Release(C.CFTypeRef(cSig))

	sig, err := CFDataToBytes(cSig)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// Sign creates the cryptographic signature for the digest using private key KeyRef and returns it as a byte slice
func (key *KeyRef) SignWithHash(digest []byte, hash crypto.Hash, publicKey crypto.PublicKey) ([]byte, error) {
	cfDigest, err := BytesToCFData(digest)
	defer Release(C.CFTypeRef(cfDigest))
	if err != nil {
		return nil, err
	}

	algo, err := getAlgo(publicKey, hash)
	if err != nil {
		return nil, err
	}
	// sign the digest
	var cErr C.CFErrorRef

	//nolint:gocritic//dupSubExpr: suspicious identical LHS and RHS for `==` operator.
	cSig := C.SecKeyCreateSignature(key.cKeyRef, algo, cfDigest, &cErr)
	if err := CFErrorError(cErr); err != nil {
		defer Release(C.CFTypeRef(cErr))
		return nil, err
	}

	//nolint:gocritic//dupSubExpr: suspicious identical LHS and RHS for `==` operator.
	defer Release(C.CFTypeRef(cSig))

	sig, err := CFDataToBytes(cSig)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (key *KeyRef) GetPersistentRef() ([]byte, error) {
	item := NewItem()
	item.SetValueRef(C.CFTypeRef(key.cKeyRef))
	item.SetSecClass(SecClassCryptoKey)
	item.SetMatchLimit(MatchLimitAll)
	item.SetReturnRef(true)
	item.SetReturnPersistentRef(true)
	item.SetReturnAttributes(true)
	res, err := QueryItem(item)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	if len(res) > 1 {
		log.Printf("More than 1 result in KeyRef.GetPersistentRef: %v\n", len(res))
	}
	for _, queryResult := range res {
		if len(queryResult.PersistentRef) > 0 {
			if queryResult.HasKey {
				return queryResult.PersistentRef, nil
			}
		}
	}
	return nil, nil
}

func (key *KeyRef) Release() {
	Release(C.CFTypeRef(key.cKeyRef))
}

// getAlgo decides which algorithm to use with this key type for the given hash.
func getAlgo(pubKey crypto.PublicKey, hash crypto.Hash) (C.SecKeyAlgorithm, error) {
	var algo C.SecKeyAlgorithm
	var err error
	switch pubKey.(type) {
	case *ecdsa.PublicKey:
		switch hash {
		case crypto.SHA1:
			algo = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA1
		case crypto.SHA256:
			algo = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA256
		case crypto.SHA384:
			algo = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA384
		case crypto.SHA512:
			algo = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA512
		default:
			err = fmt.Errorf("unsupported hash")
		}
	case *rsa.PublicKey:
		switch hash {
		case crypto.SHA1:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1
		case crypto.SHA256:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
		case crypto.SHA384:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384
		case crypto.SHA512:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512
		default:
			err = fmt.Errorf("unsupported hash")
		}
	default:
		err = fmt.Errorf("unsupported key type: %v", pubKey)
	}

	return algo, err
}

type IdentityRef struct {
	cIdentityRef C.SecIdentityRef
}

func (i *IdentityRef) GetCertificate() (*CertificateRef, error) {
	var certRef C.SecCertificateRef

	//nolint:gocritic//dupSubExpr: suspicious identical LHS and RHS for `==` operator.
	errRef := C.SecIdentityCopyCertificate(i.cIdentityRef, &certRef)
	err := checkError(errRef)
	if err != nil {
		return nil, fmt.Errorf("could not copy certificate from identity: %v", err)
	}

	cert := &CertificateRef{certRef}
	runtime.SetFinalizer(cert, func(certRef *CertificateRef) {
		Release(C.CFTypeRef(certRef.cCertificateRef))
	})

	return cert, nil
}

func (i *IdentityRef) GetKey() (*KeyRef, error) {
	var keyRef C.SecKeyRef

	//nolint:gocritic//dupSubExpr: suspicious identical LHS and RHS for `==` operator.
	errRef := C.SecIdentityCopyPrivateKey(i.cIdentityRef, &keyRef)

	err := checkError(errRef)
	if err != nil {
		return nil, fmt.Errorf("could not copy key from identity: %v", err)
	}

	key := &KeyRef{keyRef}
	runtime.SetFinalizer(key, func(keyRef *KeyRef) {
		Release(C.CFTypeRef(keyRef.cKeyRef))
	})

	return key, nil
}

// CertificateCreateWithData returns the certificate as a byte slice.
// See:https://developer.apple.com/documentation/security/1396073-seccertificatecreatewithdata
// See: https://developer.apple.com/documentation/security/certificate_key_and_trust_services/certificates/getting_a_certificate
// The certificate object for which you wish to return the DER (Distinguished Encoding Rules) representation of the X.509 certificate.
func CertificateCreateWithData(derData []byte) (*CertificateRef, error) {
	// first we need to convert the DER encoded data into a CFData we can pass into the api.
	cfData, err := BytesToCFData(derData)
	if err != nil {
		return nil, err
	}
	defer Release(C.CFTypeRef(cfData))

	certRef := C.SecCertificateCreateWithData(C.kCFAllocatorDefault, cfData)
	cert := &CertificateRef{certRef}
	runtime.SetFinalizer(cert, func(certRef *CertificateRef) {
		Release(C.CFTypeRef(certRef.cCertificateRef))
	})

	return cert, nil
}

// Using a CA that is not in the keychain for certificate trust.
// https://developer.apple.com/documentation/security/1396098-sectrustsetanchorcertificates
// 1. Convert the DER CA into bytes (CertificateCreateWithData) https://developer.apple.com/documentation/security/1396073-seccertificatecreatewithdata
// 2. Create the certificate.
// 3. Add the trust anchor to the cert.
// 4. evaluate.

// MutableArrayRef for wrapping an array.
type MutableArrayRef struct {
	arrayRef C.CFMutableArrayRef
}

// TrustCopyAnchorCertificates retrieves the certificates in the system’s store of anchor certificates (see SecTrustSetAnchorCertificates(_:_:)).
// You can use the SecCertificate objects retrieved by this function as input to other functions of this API, such as SecTrustCreateWithCertificates(_:_:_:).
// See: https://developer.apple.com/documentation/security/1401507-sectrustcopyanchorcertificates/
func TrustCopyAnchorCertificates() (*MutableArrayRef, error) {
	arrayRef := newEmptyArray(5)
	cfArray := C.CFArrayRef(arrayRef)

	// https://developer.apple.com/documentation/security/2980705-sectrustevaluatewitherror
	//nolint:gocritic//dupSubExpr: suspicious identical LHS and RHS for `==` operator.
	errCode := C.SecTrustCopyAnchorCertificates(&cfArray)
	err := checkError(errCode)
	if err != nil {
		Release(C.CFTypeRef(arrayRef))
		return nil, err
	}

	return &MutableArrayRef{arrayRef: arrayRef}, nil
}

func (a *MutableArrayRef) Append(ref C.CFTypeRef) *MutableArrayRef {
	C.CFArrayAppendValue(a.arrayRef, unsafe.Pointer(ref))

	return a
}
