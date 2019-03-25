package main

import (
	"fmt"
	"time"

	dbus "github.com/guelfey/go.dbus"
	errors "github.com/pkg/errors"
)

const SecretServiceInterface = "org.freedesktop.secrets"
const SecretServiceObjectPath = "/org/freedesktop/secrets"
const DefaultCollection = "/org/freedesktop/secrets/aliases/default"

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
	Paths     dbus.Variant // as described in https://specifications.freedesktop.org/secret-service/ch09.html
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

func (s *SecretService) UnlockItems(items []dbus.ObjectPath) (err error) {
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

func main() {
	srv, err := NewService()
	if err != nil {
		panic(err)
	}
	session, err := srv.OpenSession(AuthenticationPlain)
	if err != nil {
		panic(err)
	}
	query := map[string]string{"service": "keybase", "username": "jack"}
	items, err := srv.SearchCollection(DefaultCollection, query)
	if err != nil {
		panic(err)
	}
	item := items[0] // panic if nej. if more than 1??
	err = srv.UnlockItems([]dbus.ObjectPath{item})
	if err != nil {
		panic(err)
	}
	secret, err := srv.GetSecret(item, session)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", secret.Value)
	err = srv.LockItems([]dbus.ObjectPath{item})
	if err != nil {
		panic(err)
	}
}

// TODO does default collection always exist..?
// TODO fallback if no gnome-keyring EXPL
// upgrade path...?
