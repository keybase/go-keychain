// +build darwin ios

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
	"errors"
	"fmt"
	"math"
	"reflect"
	"unicode/utf8"
	"unsafe"
)

type KeychainError int

var (
	KeychainErrorUnimplemented         KeychainError = KeychainError(C.errSecUnimplemented)
	KeychainErrorParam                               = KeychainError(C.errSecParam)
	KeychainErrorAllocate                            = KeychainError(C.errSecAllocate)
	KeychainErrorNotAvailable                        = KeychainError(C.errSecNotAvailable)
	KeychainErrorAuthFailed                          = KeychainError(C.errSecAuthFailed)
	KeychainErrorDuplicateItem                       = KeychainError(C.errSecDuplicateItem)
	KeychainErrorItemNotFound                        = KeychainError(C.errSecItemNotFound)
	KeychainErrorInteractionNotAllowed               = KeychainError(C.errSecInteractionNotAllowed)
	KeychainErrorDecode                              = KeychainError(C.errSecDecode)
)

func checkKeychainError(errCode C.OSStatus) error {
	if errCode == C.errSecSuccess {
		return nil
	}
	return KeychainError(errCode)
}

func (k KeychainError) Error() string {
	var msg string
	// SecCopyErrorMessageString is only available on OSX, so derive manually.
	switch k {
	case KeychainErrorItemNotFound:
		msg = fmt.Sprintf("Item not found (%d)", k)
	case KeychainErrorDuplicateItem:
		msg = fmt.Sprintf("Duplicate item (%d)", k)
	default:
		msg = fmt.Sprintf("Keychain Error (%d)", k)
	}
	return msg
}

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
	SecClassGenericPassword SecClass = 1
)

var SecClassKey = C.CFTypeRef(C.kSecClass)
var secClassMap = map[SecClass]C.CFTypeRef{
	SecClassGenericPassword: C.CFTypeRef(C.kSecClassGenericPassword),
}

var (
	ServiceKey     = C.CFTypeRef(C.kSecAttrService)
	AccountKey     = C.CFTypeRef(C.kSecAttrAccount)
	AccessGroupKey = C.CFTypeRef(C.kSecAttrAccessGroup)
	DataKey        = C.CFTypeRef(C.kSecValueData)
)

type Synchronizable int

const (
	SynchronizableAny Synchronizable = 1
	SynchronizableYes                = 2
	SynchronizableNo                 = 3
)

var SynchronizableKey = C.CFTypeRef(C.kSecAttrSynchronizable)
var syncMap = map[Synchronizable]C.CFTypeRef{
	SynchronizableAny: C.CFTypeRef(C.kSecAttrSynchronizableAny),
	SynchronizableYes: C.CFTypeRef(C.kCFBooleanTrue),
	SynchronizableNo:  C.CFTypeRef(C.kCFBooleanFalse),
}

type MatchLimit int

const (
	MatchLimitDefault MatchLimit = 0
	MatchLimitOne                = 1
	MatchLimitAll                = 2
)

var MatchLimitKey = C.CFTypeRef(C.kSecMatchLimit)
var matchMap = map[MatchLimit]C.CFTypeRef{
	MatchLimitOne: C.CFTypeRef(C.kSecMatchLimitOne),
	MatchLimitAll: C.CFTypeRef(C.kSecMatchLimitAll),
}

type Return int

const (
	ReturnDefault    Return = 0
	ReturnData              = 1 // C.kSecReturnData
	ReturnAttributes        = 2 // C.kSecReturnAttributes
)

type Accessible int

const (
	AccessibleWhenUnlocked                   Accessible = 1
	AccessibleAfterFirstUnlock                          = 2
	AccessibleAlways                                    = 3
	AccessibleWhenPasscodeSetThisDeviceOnly             = 4
	AccessibleWhenUnlockedThisDeviceOnly                = 5
	AccessibleAfterFirstUnlockThisDeviceOnly            = 6
	AccessibleAccessibleAlwaysThisDeviceOnly            = 7
)

var AccessibleKey = C.CFTypeRef(C.kSecAttrAccessible)
var accessibleMap = map[Accessible]C.CFTypeRef{
	AccessibleWhenUnlocked:                   C.CFTypeRef(C.kSecAttrAccessibleWhenUnlocked),
	AccessibleAfterFirstUnlock:               C.CFTypeRef(C.kSecAttrAccessibleAfterFirstUnlock),
	AccessibleAlways:                         C.CFTypeRef(C.kSecAttrAccessibleAlways),
	AccessibleWhenPasscodeSetThisDeviceOnly:  C.CFTypeRef(C.kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly),
	AccessibleWhenUnlockedThisDeviceOnly:     C.CFTypeRef(C.kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
	AccessibleAfterFirstUnlockThisDeviceOnly: C.CFTypeRef(C.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
	AccessibleAccessibleAlwaysThisDeviceOnly: C.CFTypeRef(C.kSecAttrAccessibleAlwaysThisDeviceOnly),
}

// KeychainItem for adding, querying or deleting.
type KeychainItem struct {
	attr map[C.CFTypeRef]interface{}
}

// NewGenericPassword creates password KeychainItem for AddItem
func NewGenericPassword(service string, account string, data []byte, accessGroup string, sync Synchronizable, accessible Accessible) KeychainItem {
	attr := map[C.CFTypeRef]interface{}{
		SecClassKey: secClassMap[SecClassGenericPassword],
		ServiceKey:  service,
		AccountKey:  account,
		DataKey:     data,
	}

	attr[AccessibleKey] = accessibleMap[accessible]

	attr[SynchronizableKey] = syncMap[sync]

	if accessGroup != "" {
		attr[AccessGroupKey] = accessGroup
	}

	return KeychainItem{attr: attr}
}

// AddItem adds a KeychainItem
func AddItem(item KeychainItem) error {
	cfDict, err := convertAttr(item.attr)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(cfDict))

	errCode := C.SecItemAdd(cfDict, nil)
	err = checkKeychainError(errCode)
	return err
}

// KeychainQueryResult stores all possible results from queries.
// Not all fields all applicable all the time.
type KeychainQueryResult struct {
	Service string
	Account string
	Data    []byte
}

// NewGenericPasswordQuery creates a KeychainItem that can be used in QueryItem
func NewGenericPasswordQuery(service string, account string, matchLimit MatchLimit, returnType Return) KeychainItem {
	attr := make(map[C.CFTypeRef]interface{})

	attr[SecClassKey] = secClassMap[SecClassGenericPassword]

	if service != "" {
		attr[ServiceKey] = service
	}

	if account != "" {
		attr[AccountKey] = account
	}

	if matchLimit != MatchLimitDefault {
		attr[MatchLimitKey] = matchMap[matchLimit]
	}

	switch returnType {
	case ReturnDefault:
		// Default means don't set
	case ReturnAttributes:
		attr[C.CFTypeRef(C.kSecReturnAttributes)] = true
	case ReturnData:
		attr[C.CFTypeRef(C.kSecReturnData)] = true
	}

	return KeychainItem{attr: attr}
}

// QueryItem returns a list of query results.
func QueryItem(item KeychainItem) ([]KeychainQueryResult, error) {
	cfDict, err := convertAttr(item.attr)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(cfDict))

	var resultsRef C.CFTypeRef
	errCode := C.SecItemCopyMatching(cfDict, &resultsRef)
	if KeychainError(errCode) == KeychainErrorItemNotFound {
		return nil, nil
	}
	err = checkKeychainError(errCode)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(resultsRef)

	results := make([]KeychainQueryResult, 0, 1)

	typeID := C.CFGetTypeID(resultsRef)
	if typeID == C.CFArrayGetTypeID() {
		arr := cfArrayToArray(C.CFArrayRef(resultsRef))
		for _, dictRef := range arr {
			item := convertResult(C.CFDictionaryRef(dictRef))
			results = append(results, item)
		}
	} else if typeID == C.CFDictionaryGetTypeID() {
		item := convertResult(C.CFDictionaryRef(resultsRef))
		results = append(results, item)
	} else if typeID == C.CFDataGetTypeID() {
		b, err := cfDataToBytes(C.CFDataRef(resultsRef))
		if err != nil {
			return nil, err
		}
		item := KeychainQueryResult{Data: b}
		results = append(results, item)
	} else {
		typeDesc := C.CFCopyTypeIDDescription(typeID)
		defer C.CFRelease(C.CFTypeRef(typeDesc))
		return nil, fmt.Errorf("Invalid result type: %s", cfStringToString(typeDesc))
	}

	return results, nil
}

func convertResult(d C.CFDictionaryRef) KeychainQueryResult {
	m := cfDictionaryToMap(C.CFDictionaryRef(d))
	result := KeychainQueryResult{}
	for k, v := range m {
		switch k {
		case ServiceKey:
			result.Service = cfStringToString(C.CFStringRef(v))
		case AccountKey:
			result.Account = cfStringToString(C.CFStringRef(v))
		}
	}
	return result
}

// DeleteGenericPasswordItem removes a generic password item
func DeleteGenericPasswordItem(service string, account string) error {
	attr := map[C.CFTypeRef]interface{}{
		SecClassKey: secClassMap[SecClassGenericPassword],
		ServiceKey:  service,
		AccountKey:  account,
	}
	return DeleteItem(KeychainItem{attr: attr})
}

// DeleteItem removes a KeychainItem
func DeleteItem(item KeychainItem) error {
	cfDict, err := convertAttr(item.attr)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(cfDict))

	errCode := C.SecItemDelete(cfDict)
	return checkKeychainError(errCode)
}

// GetAccounts returns accounts for service. This is a convienience method.
func GetAccounts(service string) ([]string, error) {
	query := NewGenericPasswordQuery(service, "", MatchLimitAll, ReturnAttributes)
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

// GetGenericPassword returns password data for service and account. This is a convienence method.
func GetGenericPassword(service string, account string) ([]byte, error) {
	query := NewGenericPasswordQuery(service, account, MatchLimitOne, ReturnData)
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

// Covert attributes to CFDictionaryRef. You need to release the result.
func convertAttr(attr map[C.CFTypeRef]interface{}) (C.CFDictionaryRef, error) {
	m := make(map[C.CFTypeRef]C.CFTypeRef)
	for key, i := range attr {
		var valueRef C.CFTypeRef
		switch i.(type) {
		default:
			return nil, fmt.Errorf("Unsupported value type for keychain item: %v", reflect.TypeOf(i))
		case C.CFTypeRef:
			valueRef = i.(C.CFTypeRef)
		case bool:
			if i == true {
				valueRef = C.CFTypeRef(C.kCFBooleanTrue)
			} else {
				valueRef = C.CFTypeRef(C.kCFBooleanFalse)
			}
		case []byte:
			bytesRef, err := bytesToCFData(i.([]byte))
			if err != nil {
				return nil, err
			}
			valueRef = C.CFTypeRef(bytesRef)
			defer C.CFRelease(valueRef)
		case string:
			stringRef, err := stringToCFString(i.(string))
			if err != nil {
				return nil, err
			}
			valueRef = C.CFTypeRef(stringRef)
			defer C.CFRelease(valueRef)
		}
		m[key] = valueRef
	}

	cfDict, err := mapToCFDictionary(m)
	if err != nil {
		return nil, err
	}
	return cfDict, nil
}

// The returned CFDataRef, if non-nil, must be released via CFRelease.
func bytesToCFData(b []byte) (C.CFDataRef, error) {
	if uint64(len(b)) > math.MaxUint32 {
		return nil, errors.New("Data is too large")
	}
	var p *C.UInt8
	if len(b) > 0 {
		p = (*C.UInt8)(&b[0])
	}
	cfData := C.CFDataCreate(nil, p, C.CFIndex(len(b)))
	if cfData == nil {
		return nil, fmt.Errorf("CFDataCreate failed")
	}
	return cfData, nil
}

func cfDataToBytes(cfData C.CFDataRef) ([]byte, error) {
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(cfData)), C.int(C.CFDataGetLength(cfData))), nil
}

// The returned CFDictionaryRef, if non-nil, must be released via CFRelease.
func mapToCFDictionary(m map[C.CFTypeRef]C.CFTypeRef) (C.CFDictionaryRef, error) {
	var keys, values []unsafe.Pointer
	for key, value := range m {
		keys = append(keys, unsafe.Pointer(key))
		values = append(values, unsafe.Pointer(value))
	}
	numValues := len(values)
	var keysPointer, valuesPointer *unsafe.Pointer
	if numValues > 0 {
		keysPointer = &keys[0]
		valuesPointer = &values[0]
	}
	cfDict := C.CFDictionaryCreate(nil, keysPointer, valuesPointer, C.CFIndex(numValues), &C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks)
	if cfDict == nil {
		return nil, fmt.Errorf("CFDictionaryCreate failed")
	}
	return cfDict, nil
}

// The returned CFStringRef, if non-nil, must be released via CFRelease.
func stringToCFString(s string) (C.CFStringRef, error) {
	if !utf8.ValidString(s) {
		return nil, errors.New("Invalid UTF-8 string")
	}
	if uint64(len(s)) > math.MaxUint32 {
		return nil, errors.New("String is too large")
	}

	bytes := []byte(s)
	var p *C.UInt8
	if len(bytes) > 0 {
		p = (*C.UInt8)(&bytes[0])
	}
	return C.CFStringCreateWithBytes(nil, p, C.CFIndex(len(s)), C.kCFStringEncodingUTF8, C.false), nil
}

func cfArrayToArray(cfArray C.CFArrayRef) (a []C.CFTypeRef) {
	count := C.CFArrayGetCount(cfArray)
	if count > 0 {
		a = make([]C.CFTypeRef, count)
		C.CFArrayGetValues(cfArray, C.CFRange{0, count}, (*unsafe.Pointer)(&a[0]))
	}
	return
}

func cfDictionaryToMap(cfDict C.CFDictionaryRef) (m map[C.CFTypeRef]C.CFTypeRef) {
	count := C.CFDictionaryGetCount(cfDict)
	if count > 0 {
		keys := make([]C.CFTypeRef, count)
		values := make([]C.CFTypeRef, count)
		C.CFDictionaryGetKeysAndValues(cfDict, (*unsafe.Pointer)(&keys[0]), (*unsafe.Pointer)(&values[0]))
		m = make(map[C.CFTypeRef]C.CFTypeRef, count)
		for i := C.CFIndex(0); i < count; i++ {
			m[keys[i]] = values[i]
		}
	}
	return
}

func cfStringToString(s C.CFStringRef) string {
	p := C.CFStringGetCStringPtr(s, C.kCFStringEncodingUTF8)
	if p != nil {
		return C.GoString(p)
	}
	length := C.CFStringGetLength(s)
	if length == 0 {
		return ""
	}
	maxBufLen := C.CFStringGetMaximumSizeForEncoding(length, C.kCFStringEncodingUTF8)
	if maxBufLen == 0 {
		return ""
	}
	buf := make([]byte, maxBufLen)
	var usedBufLen C.CFIndex
	_ = C.CFStringGetBytes(s, C.CFRange{0, length}, C.kCFStringEncodingUTF8, C.UInt8(0), C.false, (*C.UInt8)(&buf[0]), maxBufLen, &usedBufLen)
	return string(buf[:usedBufLen])
}
