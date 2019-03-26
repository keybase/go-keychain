package main

import (
	"fmt"
	"time"

	dbus "github.com/guelfey/go.dbus"
	errors "github.com/pkg/errors"
)

const SecretServiceInterface = "org.freedesktop.secrets"
const SecretServiceObjectPath dbus.ObjectPath = "/org/freedesktop/secrets"
const DefaultCollection dbus.ObjectPath = "/org/freedesktop/secrets/aliases/default"

type authenticationMode string

const AuthenticationPlain authenticationMode = "plain"

type Attributes map[string]string

type Secret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

type PromptCompletedResult struct {
	Dismissed bool
	Paths     dbus.Variant
}

type SecretService struct {
	conn     *dbus.Conn
	signalCh <-chan *dbus.Signal
}

func NewService() (*SecretService, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return nil, errors.Wrap(err, "failed to open dbus connection")
	}
	signalCh := make(chan *dbus.Signal, 16)
	conn.Signal(signalCh)
	return &SecretService{conn: conn, signalCh: signalCh}, nil
}

func (s *SecretService) ServiceObj() *dbus.Object {
	return s.conn.Object(SecretServiceInterface, SecretServiceObjectPath)
}

func (s *SecretService) Obj(path dbus.ObjectPath) *dbus.Object {
	return s.conn.Object(SecretServiceInterface, path)
}

func (s *SecretService) OpenSession(mode authenticationMode) (session dbus.ObjectPath, err error) {
	var dummy dbus.Variant
	err = s.ServiceObj().
		Call("org.freedesktop.Secret.Service.OpenSession", 0, mode, dbus.MakeVariant("")).
		Store(&dummy, &session)
	if err != nil {
		return "", errors.Wrap(err, "failed to open secretservice session")
	}
	return session, nil
}

func (s *SecretService) SearchCollection(collection dbus.ObjectPath, attributes Attributes) (items []dbus.ObjectPath, err error) {
	err = s.Obj(collection).
		Call("org.freedesktop.Secret.Collection.SearchItems", 0, attributes).
		Store(&items)
	if err != nil {
		return nil, errors.Wrap(err, "failed to search collection")
	}
	return items, nil
}

func (s *SecretService) CreateItem(collection dbus.ObjectPath, properties map[string]dbus.Variant, secret Secret, replace bool) (item dbus.ObjectPath, err error) {
	var prompt dbus.ObjectPath
	err = s.Obj(collection).
		Call("org.freedesktop.Secret.Collection.CreateItem", 0, properties, secret, replace).
		Store(&item, &prompt)
	if err != nil {
		return "", errors.Wrap(err, "failed to create item")
	}
	_, err = s.PromptAndWait(prompt)
	if err != nil {
		return "", err
	}
	return item, nil
}

func (s *SecretService) GetSecret(item dbus.ObjectPath, session dbus.ObjectPath) (secret *Secret, err error) {
	var secretI []interface{}
	err = s.Obj(item).
		Call("org.freedesktop.Secret.Item.GetSecret", 0, session).
		Store(&secretI)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get secret")
	}
	secret = new(Secret)
	err = dbus.Store(secretI, &secret.Session, &secret.Parameters, &secret.Value, &secret.ContentType)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal get secret result")
	}
	return secret, nil
}

const NullPrompt = "/"

func (s *SecretService) Unlock(items []dbus.ObjectPath) (err error) {
	var dummy []dbus.ObjectPath
	var prompt dbus.ObjectPath
	err = s.ServiceObj().
		Call("org.freedesktop.Secret.Service.Unlock", 0, items).
		Store(&dummy, &prompt)
	if err != nil {
		return errors.Wrap(err, "failed to unlock items")
	}
	paths, err := s.PromptAndWait(prompt)
	if err != nil {
		return errors.Wrap(err, "failed to prompt")
	}
	fmt.Println("unlocked paths %+v", paths)
	return nil
}

func (s *SecretService) LockItems(items []dbus.ObjectPath) (err error) {
	var dummy []dbus.ObjectPath
	var prompt dbus.ObjectPath
	err = s.ServiceObj().
		Call("org.freedesktop.Secret.Service.Lock", 0, items).
		Store(&dummy, &prompt)
	if err != nil {
		return errors.Wrap(err, "failed to lock items")
	}
	paths, err := s.PromptAndWait(prompt)
	if err != nil {
		return errors.Wrap(err, "failed to prompt")
	}
	fmt.Printf("unlocked paths %+v\n", paths)

	return nil
}

// PromptAndWait is NOT thread-safe.
func (s *SecretService) PromptAndWait(prompt dbus.ObjectPath) (paths *dbus.Variant, err error) {
	if prompt == NullPrompt {
		return nil, nil
	}
	call := s.Obj(prompt).Call("org.freedesktop.Secret.Prompt.Prompt", 0, "Keyring Prompt")
	if call.Err != nil {
		return nil, errors.Wrap(err, "failed to prompt")
	}
	for {
		var result PromptCompletedResult
		select {
		case signal := <-s.signalCh:
			if signal.Name != "org.freedesktop.Secret.Prompt.Completed" {
				continue
			}
			err = dbus.Store(signal.Body, &result.Dismissed, &result.Paths)
			if err != nil {
				return nil, errors.Wrap(err, "failed to unmarshal prompt result")
			}
			if result.Dismissed {
				return nil, errors.New("prompt dismissed")
			}
			return &result.Paths, nil
		case <-time.After(30 * time.Second):
			return nil, errors.New("prompt timed out")
		}
	}
}

func main2() error {
	srv, err := NewService()
	if err != nil {
		return err
	}
	session, err := srv.OpenSession(AuthenticationPlain)
	if err != nil {
		return err
	}
	query := map[string]string{"service": "keybase", "username": "t_alice"}
	items, err := srv.SearchCollection(DefaultCollection, query)
	if err != nil {
		return err
	}
	item := items[0] // panic if nej. if more than 1??
	err = srv.Unlock([]dbus.ObjectPath{item})
	if err != nil {
		return err
	}
	secret, err := srv.GetSecret(item, session)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", secret.Value)
	err = srv.LockItems([]dbus.ObjectPath{item})
	if err != nil {
		return err
	}
	props := make(map[string]dbus.Variant)
	props["org.freedesktop.Secret.Item.Label"] = dbus.MakeVariant("alice@keybaseee")
	props["org.freedesktop.Secret.Item.Attributes"] = dbus.MakeVariant(map[string]string{
		"service":  "keybase",
		"username": "t_alice",
	})
	newSecret := Secret{
		Session:     session,
		Parameters:  nil,
		Value:       []byte("naww"),
		ContentType: "text/plain",
	}
	err = srv.Unlock([]dbus.ObjectPath{DefaultCollection})
	if err != nil {
		return err
	}
	newItem, err := srv.CreateItem(DefaultCollection, props, newSecret, true)
	if err != nil {
		return err
	}
	fmt.Printf("%+v\n", newItem)
	return nil
}

func main() {
	err := main2()
	if err != nil {
		panic(fmt.Sprintf("%+v\n", err))
	}
}

// TODO does default collection always exist..? (no)
// TODO fallback if no gnome-keyring EXPL
// upgrade path...?
// if there are more than 1, what should we do? just delete all of them and fail?
// TODO dh ietf
