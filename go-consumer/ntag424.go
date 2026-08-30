// Package ntag424 implements the NTAG424 DNA / boltcard crypto checks
// exercised by the shared cross-language vector suite
// (Amperstrand/ntag424-vectors).
//
// The SUN MAC verification path is a port of the Go boltcard reference:
// crypto/crypto.go Aes_cmac and lnurlw/lnurlw_request.go check_cmac
// (github.com/boltcard/boltcard). The deterministic key derivation
// follows the boltcard scheme pinned by the vectors (tags 2D003F75..2D003F7B).
package ntag424

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"

	"github.com/aead/cmac"
)

// AesCmac computes AES-128-CMAC (RFC 4493) of msg under key.
func AesCmac(key, msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cmac.Sum(msg, block, 16)
}

// BuildSV2 assembles SV2 = 3C C3 00 01 00 80 || UID(7) || SDMReadCtr(3),
// copying the counter bytes verbatim (PICCData[8..11] order).
// Port of boltcard lnurlw check_cmac SV2 construction.
func BuildSV2(uid, counterBytes []byte) ([16]byte, error) {
	var sv2 [16]byte
	if len(uid) != 7 || len(counterBytes) != 3 {
		return sv2, errBadLength
	}
	copy(sv2[0:], []byte{0x3c, 0xc3, 0x00, 0x01, 0x00, 0x80})
	copy(sv2[6:], uid)
	copy(sv2[13:], counterBytes)
	return sv2, nil
}

// VerifySunMac runs the AN12196 §3.4.4.2.1 chain with an empty MAC input:
// Ks = CMAC(k2, SV2); CMACt = odd-index bytes of CMAC(Ks, empty);
// constant-time-free comparison against macT. Port of boltcard
// crypto.Aes_cmac.
func VerifySunMac(k2, uid, counterBytes, macT []byte) (bool, error) {
	sv2, err := BuildSV2(uid, counterBytes)
	if err != nil {
		return false, err
	}
	ks, err := AesCmac(k2, sv2[:])
	if err != nil {
		return false, err
	}
	cm, err := AesCmac(ks, nil)
	if err != nil {
		return false, err
	}
	ct := []byte{cm[1], cm[3], cm[5], cm[7], cm[9], cm[11], cm[13], cm[15]}
	return bytes.Equal(ct, macT), nil
}

// PiccData is the decrypted PICCENCData payload.
type PiccData struct {
	Decrypted    [16]byte
	UID          [7]byte
	CounterBytes [3]byte
}

// DecryptPicc decrypts a single-block PICCENCData blob with AES-CBC under
// a zero IV (boltcard crypto.Aes_decrypt) and parses PICCDataTag || UID ||
// SDMReadCtr. CounterBytes are the verbatim plaintext bytes 8..10.
func DecryptPicc(key, piccEnc []byte) (PiccData, error) {
	var p PiccData
	if len(piccEnc) != 16 {
		return p, errBadLength
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return p, err
	}
	iv := make([]byte, 16)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(p.Decrypted[:], piccEnc)
	if p.Decrypted[0] != 0xc7 {
		return p, errBadPiccTag
	}
	copy(p.UID[:], p.Decrypted[1:8])
	copy(p.CounterBytes[:], p.Decrypted[8:11])
	return p, nil
}

type errString string

func (e errString) Error() string { return string(e) }

const (
	errBadPiccTag = errString("invalid PICCDataTag byte")
	errBadLength  = errString("unexpected input length")
)

// Deterministic key-derivation tags (boltcard scheme).
var (
	tagCardKey = mustHex("2d003f75")
	tagK0      = mustHex("2d003f76")
	tagK1      = mustHex("2d003f77")
	tagK2      = mustHex("2d003f78")
	tagK3      = mustHex("2d003f79")
	tagK4      = mustHex("2d003f7a")
	tagCardID  = mustHex("2d003f7b")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// DerivedKeys is the boltcard deterministic key set for one card.
type DerivedKeys struct {
	CardKey []byte
	K0      []byte
	K1      []byte
	K2      []byte
	K3      []byte
	K4      []byte
	CardID  []byte
}

// DeriveKeys computes the boltcard deterministic key set:
// card_key = CMAC(issuer, 2D003F75 || UID || version_u32_le), then the
// per-tag derivations with card_key (k1 uses the issuer key).
func DeriveKeys(issuerKey, uid []byte, version uint32) (DerivedKeys, error) {
	var dk DerivedKeys
	if len(issuerKey) != 16 || len(uid) != 7 {
		return dk, errBadLength
	}
	msg := make([]byte, 0, 4+7+len(tagCardKey))
	msg = append(msg, tagCardKey...)
	msg = append(msg, uid...)
	var ver [4]byte
	binary.LittleEndian.PutUint32(ver[:], version)
	msg = append(msg, ver[:]...)

	cardKey, err := AesCmac(issuerKey, msg)
	if err != nil {
		return dk, err
	}
	dk.CardKey = cardKey
	if dk.K0, err = AesCmac(cardKey, tagK0); err != nil {
		return dk, err
	}
	if dk.K1, err = AesCmac(issuerKey, tagK1); err != nil {
		return dk, err
	}
	if dk.K2, err = AesCmac(cardKey, tagK2); err != nil {
		return dk, err
	}
	if dk.K3, err = AesCmac(cardKey, tagK3); err != nil {
		return dk, err
	}
	if dk.K4, err = AesCmac(cardKey, tagK4); err != nil {
		return dk, err
	}
	// ID = PRF(IssuerKey, '2d003f7b' || UID) per the pinned spec quote in
	// bolty-rs derivation.rs (the fixture TOML metadata line mislabels the key).
	idMsg := append(append([]byte{}, tagCardID...), uid...)
	dk.CardID, err = AesCmac(issuerKey, idMsg)
	return dk, err
}
