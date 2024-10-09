//Louie Rivera
package chatterbox

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// Labels for key derivation
const HANDSHAKE_CHECK_LABEL byte = 0x11
const ROOT_LABEL = 0x22
const CHAIN_LABEL = 0x33
const KEY_LABEL = 0x44

// Chatter represents a chat participant. Each Chatter has a single long-term
// key Identity, and a map of open sessions with other users (indexed by their
// identity keys).
type Chatter struct {
	Identity  *KeyPair
	Sessions  map[PublicKey]*Session
	NewSender bool
}

// Session represents an open session between one chatter and another.
type Session struct {
	MyDHRatchet       *KeyPair
	PartnerDHRatchet  *PublicKey
	RootChain         *SymmetricKey
	SendChain         *SymmetricKey
	ReceiveChain      *SymmetricKey
	CachedReceiveKeys map[int]*SymmetricKey
	SendCounter       int
	LastUpdate        int
	ReceiveCounter    int
}

// Message represents a message as sent over an untrusted network.
type Message struct {
	Sender        *PublicKey
	Receiver      *PublicKey
	NextDHRatchet *PublicKey
	Counter       int
	LastUpdate    int
	Ciphertext    []byte
	IV            []byte
}

// EncodeAdditionalData encodes all of the non-ciphertext fields of a message
// into a single byte array, suitable for use as additional authenticated data
// in an AEAD scheme.
func (m *Message) EncodeAdditionalData() []byte {
	buf := make([]byte, 8+3*FINGERPRINT_LENGTH)

	binary.LittleEndian.PutUint32(buf, uint32(m.Counter))
	binary.LittleEndian.PutUint32(buf[4:], uint32(m.LastUpdate))

	if m.Sender != nil {
		copy(buf[8:], m.Sender.Fingerprint())
	}
	if m.Receiver != nil {
		copy(buf[8+FINGERPRINT_LENGTH:], m.Receiver.Fingerprint())
	}
	if m.NextDHRatchet != nil {
		copy(buf[8+2*FINGERPRINT_LENGTH:], m.NextDHRatchet.Fingerprint())
	}

	return buf
}

// NewChatter creates and initializes a new Chatter object.
func NewChatter() *Chatter {
	c := new(Chatter)
	c.Identity = GenerateKeyPair()
	c.Sessions = make(map[PublicKey]*Session)
	return c
}

// EndSession erases all data for a session with the designated partner.
func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {
	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return errors.New("Don't have that session open to tear down")
	}

	session := c.Sessions[*partnerIdentity]
	session.MyDHRatchet.Zeroize()
	session.ReceiveChain.Zeroize()
	session.RootChain.Zeroize()
	session.CachedReceiveKeys = nil

	delete(c.Sessions, *partnerIdentity)
	return nil
}

// InitiateHandshake prepares the first message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the initiator.
func (c *Chatter) InitiateHandshake(partnerIdentity *PublicKey) (*PublicKey, error) {
	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, errors.New("Already have session open")
	}

	c.Sessions[*partnerIdentity] = &Session{
		MyDHRatchet:       GenerateKeyPair(),
		CachedReceiveKeys: make(map[int]*SymmetricKey),
	}

	return &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey, nil
}

// ReturnHandshake prepares the second message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the responder.
func (c *Chatter) ReturnHandshake(partnerIdentity, partnerEphemeral *PublicKey) (*PublicKey, *SymmetricKey, error) {
	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, nil, errors.New("Already have session open")
	}

	myKey := GenerateKeyPair()
	gAb := DHCombine(partnerIdentity, &myKey.PrivateKey)
	gaB := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)
	gab := DHCombine(partnerEphemeral, &myKey.PrivateKey)
	rootKey := CombineKeys(gAb, gaB, gab)
	checkKey := rootKey.DeriveKey(HANDSHAKE_CHECK_LABEL)

	c.Sessions[*partnerIdentity] = &Session{
		MyDHRatchet:       myKey,
		PartnerDHRatchet:  partnerEphemeral,
		RootChain:         rootKey,
		CachedReceiveKeys: make(map[int]*SymmetricKey),
	}

	return &myKey.PublicKey, checkKey, nil
}

// FinalizeHandshake lets the initiator receive the responder's ephemeral key
// and finalize the handshake. The partner which calls this method is the initiator.
func (c *Chatter) FinalizeHandshake(partnerIdentity, partnerEphemeral *PublicKey) (*SymmetricKey, error) {
	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't finalize session, not yet open")
	}

	session := c.Sessions[*partnerIdentity]
	gAb := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)
	gaB := DHCombine(partnerIdentity, &session.MyDHRatchet.PrivateKey)
	gab := DHCombine(partnerEphemeral, &session.MyDHRatchet.PrivateKey)
	rootKey := CombineKeys(gAb, gaB, gab)
	checkKey := rootKey.DeriveKey(HANDSHAKE_CHECK_LABEL)

	session.RootChain = rootKey
	session.PartnerDHRatchet = partnerEphemeral

	return checkKey, nil
}

// SendMessage is used to send the given plaintext string as a message.
func (c *Chatter) SendMessage(partnerIdentity *PublicKey, plaintext string) (*Message, error) {
    if _, exists := c.Sessions[*partnerIdentity]; !exists {
        return nil, errors.New("Can't send message to partner with no open session")
    }

    session := c.Sessions[*partnerIdentity]
    if session.SendCounter == 0 || c.NewSender {
        session.LastUpdate = session.SendCounter
        session.MyDHRatchet = GenerateKeyPair()
        newRatchet := DHCombine(session.PartnerDHRatchet, &session.MyDHRatchet.PrivateKey)
        session.RootChain = ratchetRootKey(session.RootChain, newRatchet)
        session.SendChain = session.RootChain.DeriveKey(CHAIN_LABEL)
        c.NewSender = false
    } else {
        session.SendChain = ratchetForward(session.SendChain)
    }

    msgKey := deriveMessageKey(session.SendChain)
    iv := NewIV()
    message := &Message{
        Sender:        &c.Identity.PublicKey,
        Receiver:      partnerIdentity,
        IV:            iv,
        NextDHRatchet: &session.MyDHRatchet.PublicKey,
        Counter:       session.SendCounter,
        LastUpdate:    session.LastUpdate,
    }
    additionalData := message.EncodeAdditionalData()
    message.Ciphertext = msgKey.AuthenticatedEncrypt(plaintext, additionalData, iv)

    session.SendCounter++

    return message, nil
}

func (c *Chatter) ReceiveMessage(message *Message) (string, error) {
	session, exists := c.Sessions[*message.Sender]
	if !exists {
		return "", errors.New("Can't receive message from partner with no open session")
	}

	// Handle out-of-order messages
	if message.Counter > session.ReceiveCounter {
		// Advance the receiving chain to the correct state
		for session.ReceiveCounter < message.Counter {
			if session.ReceiveCounter == session.LastUpdate {
				session.PartnerDHRatchet = message.NextDHRatchet
				newRatchet := DHCombine(message.NextDHRatchet, &session.MyDHRatchet.PrivateKey)
				session.RootChain = ratchetRootKey(session.RootChain, newRatchet)
				session.ReceiveChain = session.RootChain.DeriveKey(CHAIN_LABEL)
			} else {
				session.ReceiveChain = ratchetForward(session.ReceiveChain)
			}
			session.CachedReceiveKeys[session.ReceiveCounter] = deriveMessageKey(session.ReceiveChain)
			session.ReceiveCounter++
		}
	}

	// Handle in-order or late messages
	if message.Counter < session.ReceiveCounter {
		key, exists := session.CachedReceiveKeys[message.Counter]
		if !exists {
			return "", errors.New("Message key not found in cache")
		}
		plaintext, err := key.AuthenticatedDecrypt(message.Ciphertext, message.EncodeAdditionalData(), message.IV)
		key.Zeroize()
		if err != nil {
			return "", errors.New("corrupted message")
		}
		delete(session.CachedReceiveKeys, message.Counter)
		return plaintext, nil
	}

	// Normal in-order message processing
	if session.ReceiveCounter == session.LastUpdate && !session.PartnerDHRatchet.Equals(message.NextDHRatchet) {
		session.PartnerDHRatchet = message.NextDHRatchet
		newRatchet := DHCombine(message.NextDHRatchet, &session.MyDHRatchet.PrivateKey)
		session.RootChain = ratchetRootKey(session.RootChain, newRatchet)
		session.ReceiveChain = session.RootChain.DeriveKey(CHAIN_LABEL)
	} else {
		session.ReceiveChain = ratchetForward(session.ReceiveChain)
	}

	key := deriveMessageKey(session.ReceiveChain)
	plaintext, err := key.AuthenticatedDecrypt(message.Ciphertext, message.EncodeAdditionalData(), message.IV)
	key.Zeroize()
	if err != nil {
		return "", errors.New("corrupted message")
	}

	session.ReceiveCounter = message.Counter + 1
	return plaintext, nil
}

// Helper functions

func deriveMessageKey(chainKey *SymmetricKey) *SymmetricKey {
	msgKey := chainKey.DeriveKey(KEY_LABEL)
	return msgKey
}

func ratchetForward(chainKey *SymmetricKey) *SymmetricKey {
	newChainKey := chainKey.DeriveKey(CHAIN_LABEL)
	return newChainKey
}

func ratchetRootKey(oldRootKey, dhValue *SymmetricKey) *SymmetricKey {
	ratchetedKey := oldRootKey.DeriveKey(ROOT_LABEL)
	newRootKey := CombineKeys(ratchetedKey, dhValue)
	return newRootKey
}

func (p *PublicKey) Equals(other *PublicKey) bool {
	return p.X.Cmp(other.X) == 0 && p.Y.Cmp(other.Y) == 0
}

type DHRatchetKey struct {
	PublicKey  [32]byte
	PrivateKey [32]byte
}

// Equals checks if two DH ratchet keys are equal
func (k *DHRatchetKey) Equals(other *DHRatchetKey) bool {
	return bytes.Equal(k.PublicKey[:], other.PublicKey[:])
}
