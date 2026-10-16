package internal

import "errors"

// ErrNoCredential is returned by getters when authentication failed at startup.
var ErrNoCredential = errors.New("no Azure credential available")

// Valid reports whether getters can use the session.
func (s Session) Valid() error {
	if s.CredentialErr != nil {
		return s.CredentialErr
	}
	if s.Credential == nil {
		return ErrNoCredential
	}
	return nil
}
