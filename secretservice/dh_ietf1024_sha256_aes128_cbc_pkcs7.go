// This file implements a basic Diffie-Hellman for groups with modular
// exponentiation operators. In particular, it is used in this package
// to implement the Diffie-Hellman KEX over the Second Oakley Group.
// meant only for use for securing the channel to the D-Bus Secret Service.
// Much of the code in this file is derived from package
// golang.org/x/crypto/ssh:kex.go, and is replicated here because the relevant
// variables and methods are not exported or easily accessible.
// Note that this protocol is NOT authenticated, NOT secure against malleation
// and is NOT CCA2-secure. It is only meant to hide the D-Bus messages from any
// system services that may be logging everything.

package secretservice

import (
	"crypto/sha256"
	"io"
	"math/big"

	errors "github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"
)

type dhGroup struct {
	g, p, pMinus1 *big.Int
}

var bigOne = big.NewInt(1)

func (group *dhGroup) diffieHellman(theirPublic, myPrivate *big.Int) (*big.Int, error) {
	if theirPublic.Cmp(bigOne) <= 0 || theirPublic.Cmp(group.pMinus1) >= 0 {
		return nil, errors.New("ssh: DH parameter out of bounds")
	}
	return new(big.Int).Exp(theirPublic, myPrivate, group.p), nil
}

func rfc2409SecondOakleyGroup() *dhGroup {
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
	return &dhGroup{
		g:       new(big.Int).SetInt64(2),
		p:       p,
		pMinus1: new(big.Int).Sub(p, bigOne),
	}
}

func keygenDHIETF1024SHA256AES128CBCPKCS7(group dhGroup, theirPublic *big.Int, myPrivate *big.Int) ([]byte, error) {
	sharedSecret, err := group.diffieHellman(theirPublic, myPrivate)
	if err != nil {
		return nil, err
	}
	sharedSecretBytes := sharedSecret.Bytes()

	r := hkdf.New(sha256.New, sharedSecretBytes, nil, nil)

	aesKey := make([]byte, 128)
	_, err = io.ReadFull(r, aesKey)
	if err != nil {
		return nil, err
	}

	return aesKey, nil
}

func UnauthenticatedAESEncrypt(plaintext []byte, key []byte) ([]byte, error) {
	return nil, nil
}
