package ntag424

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vectorInput struct {
	Op           string  `json:"op"`
	Key          string  `json:"key"`
	Message      string  `json:"message"`
	PiccEncData  string  `json:"picc_enc_data"`
	UID          string  `json:"uid"`
	CounterBytes string  `json:"counter_bytes"`
	IssuerKey    string  `json:"issuer_key"`
	Version      *uint32 `json:"version"`
	K1           string  `json:"k1"`
	K2           string  `json:"k2"`
	P            string  `json:"p"`
	C            string  `json:"c"`
}

type vectorExpected struct {
	Cmac          string `json:"cmac"`
	Decrypted     string `json:"decrypted"`
	UID           string `json:"uid"`
	CounterBytes  string `json:"counter_bytes"`
	Sv2           string `json:"sv2"`
	CmacTruncated string `json:"cmac_truncated"`
	CardKey       string `json:"card_key"`
	K0            string `json:"k0"`
	K1            string `json:"k1"`
	K2            string `json:"k2"`
	K3            string `json:"k3"`
	K4            string `json:"k4"`
	CardID        string `json:"card_id"`
	DecryptedP    string `json:"decrypted_p"`
	DerivedMacKey string `json:"derived_mac_key"`
	FullCmac      string `json:"full_cmac"`
}

type vector struct {
	ID       string         `json:"id"`
	Category string         `json:"category"`
	Negative bool           `json:"negative"`
	Input    vectorInput    `json:"input"`
	Expected vectorExpected `json:"expected"`
	Origin   string         `json:"origin"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile("vectors.json")
	if err != nil {
		t.Fatalf("read vendored vectors.json: %v", err)
	}
	var doc struct {
		SchemaVersion int      `json:"schema_version"`
		Vectors       []vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse vectors.json: %v", err)
	}
	if doc.SchemaVersion != 1 {
		t.Fatalf("unexpected schema_version %d", doc.SchemaVersion)
	}
	if len(doc.Vectors) != 46 {
		t.Fatalf("vendored vectors.json changed size: %d vectors", len(doc.Vectors))
	}
	return doc.Vectors
}

func mustUnhex(t *testing.T, s, field, id string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("vector %s: field %s: %v", id, field, err)
	}
	return b
}

func byOp(vs []vector, op string) []vector {
	var out []vector
	for _, v := range vs {
		if v.Input.Op == op {
			out = append(out, v)
		}
	}
	return out
}

func eqHex(t *testing.T, id, field string, got []byte, want string) {
	t.Helper()
	if want == "" {
		t.Fatalf("vector %s: expected field %s missing", id, field)
	}
	if !bytes.Equal(got, mustUnhex(t, want, field, id)) {
		t.Errorf("vector %s: %s = %x, want %s", id, field, got, want)
	}
}

func TestSharedVectors(t *testing.T) {
	vs := loadVectors(t)

	t.Run("aes_cmac", func(t *testing.T) {
		got := byOp(vs, "aes_cmac")
		if len(got) != 5 {
			t.Fatalf("expected 5 aes_cmac vectors, got %d", len(got))
		}
		for _, v := range got {
			mac, err := AesCmac(
				mustUnhex(t, v.Input.Key, "key", v.ID),
				mustUnhex(t, v.Input.Message, "message", v.ID),
			)
			if err != nil {
				t.Fatalf("vector %s: %v", v.ID, err)
			}
			eqHex(t, v.ID, "cmac", mac, v.Expected.Cmac)
		}
	})

	t.Run("picc_decrypt", func(t *testing.T) {
		got := byOp(vs, "picc_decrypt")
		if len(got) != 1 {
			t.Fatalf("expected 1 picc_decrypt vector, got %d", len(got))
		}
		for _, v := range got {
			p, err := DecryptPicc(
				mustUnhex(t, v.Input.Key, "key", v.ID),
				mustUnhex(t, v.Input.PiccEncData, "picc_enc_data", v.ID),
			)
			if err != nil {
				t.Fatalf("vector %s: %v", v.ID, err)
			}
			eqHex(t, v.ID, "decrypted", p.Decrypted[:], v.Expected.Decrypted)
			eqHex(t, v.ID, "uid", p.UID[:], v.Expected.UID)
			eqHex(t, v.ID, "counter_bytes", p.CounterBytes[:], v.Expected.CounterBytes)
		}
	})

	t.Run("sv2_build", func(t *testing.T) {
		got := byOp(vs, "sv2_build")
		if len(got) != 2 {
			t.Fatalf("expected 2 sv2_build vectors, got %d", len(got))
		}
		for _, v := range got {
			sv2, err := BuildSV2(
				mustUnhex(t, v.Input.UID, "uid", v.ID),
				mustUnhex(t, v.Input.CounterBytes, "counter_bytes", v.ID),
			)
			if err != nil {
				t.Fatalf("vector %s: %v", v.ID, err)
			}
			eqHex(t, v.ID, "sv2", sv2[:], v.Expected.Sv2)
		}
	})

	t.Run("sun_mac", func(t *testing.T) {
		got := byOp(vs, "sun_mac")
		if len(got) != 1 {
			t.Fatalf("expected 1 sun_mac vector, got %d", len(got))
		}
		for _, v := range got {
			ok, err := VerifySunMac(
				mustUnhex(t, v.Input.Key, "key", v.ID),
				mustUnhex(t, v.Input.UID, "uid", v.ID),
				mustUnhex(t, v.Input.CounterBytes, "counter_bytes", v.ID),
				mustUnhex(t, v.Expected.CmacTruncated, "cmac_truncated", v.ID),
			)
			if err != nil {
				t.Fatalf("vector %s: %v", v.ID, err)
			}
			if !ok {
				t.Errorf("vector %s: SUN MAC %s not verified", v.ID, v.Expected.CmacTruncated)
			}
		}
	})

	t.Run("derive_keys", func(t *testing.T) {
		got := byOp(vs, "derive_keys")
		if len(got) != 26 {
			t.Fatalf("expected 26 derive_keys vectors, got %d", len(got))
		}
		for _, v := range got {
			dk, err := DeriveKeys(
				mustUnhex(t, v.Input.IssuerKey, "issuer_key", v.ID),
				mustUnhex(t, v.Input.UID, "uid", v.ID),
				*v.Input.Version,
			)
			if err != nil {
				t.Fatalf("vector %s: %v", v.ID, err)
			}
			// Sources published subsets; verify exactly the pinned fields.
			if v.Expected.CardKey != "" {
				eqHex(t, v.ID, "card_key", dk.CardKey, v.Expected.CardKey)
			}
			if v.Expected.K0 != "" {
				eqHex(t, v.ID, "k0", dk.K0, v.Expected.K0)
			}
			if v.Expected.K1 != "" {
				eqHex(t, v.ID, "k1", dk.K1, v.Expected.K1)
			}
			if v.Expected.K2 != "" {
				eqHex(t, v.ID, "k2", dk.K2, v.Expected.K2)
			}
			if v.Expected.K3 != "" {
				eqHex(t, v.ID, "k3", dk.K3, v.Expected.K3)
			}
			if v.Expected.K4 != "" {
				eqHex(t, v.ID, "k4", dk.K4, v.Expected.K4)
			}
			if v.Expected.CardID != "" {
				eqHex(t, v.ID, "card_id", dk.CardID, v.Expected.CardID)
			}
		}
	})

	t.Run("sdm_full", func(t *testing.T) {
		got := byOp(vs, "sdm_full")
		if len(got) != 11 {
			t.Fatalf("expected 11 sdm_full vectors, got %d", len(got))
		}
		negatives := 0
		for _, v := range got {
			k1 := mustUnhex(t, v.Input.K1, "k1", v.ID)
			k2 := mustUnhex(t, v.Input.K2, "k2", v.ID)

			if v.Negative {
				negatives++
				// The chain must reject: decrypt gate failure OR SUN-MAC
				// mismatch. expected fields are documentation only.
				p, err := DecryptPicc(k1, mustUnhex(t, v.Input.P, "p", v.ID))
				if err == nil {
					ok, err := VerifySunMac(k2, p.UID[:], p.CounterBytes[:],
						mustUnhex(t, v.Input.C, "c", v.ID))
					if err != nil {
						t.Fatalf("vector %s: %v", v.ID, err)
					}
					if ok {
						t.Errorf("negative vector %s: verification must reject", v.ID)
					}
				}
				continue
			}

			p, err := DecryptPicc(k1, mustUnhex(t, v.Input.P, "p", v.ID))
			if err != nil {
				t.Fatalf("vector %s: %v", v.ID, err)
			}
			eqHex(t, v.ID, "decrypted_p", p.Decrypted[:], v.Expected.DecryptedP)
			eqHex(t, v.ID, "uid", p.UID[:], v.Expected.UID)
			eqHex(t, v.ID, "counter_bytes", p.CounterBytes[:], v.Expected.CounterBytes)

			sv2, err := BuildSV2(p.UID[:], p.CounterBytes[:])
			if err != nil {
				t.Fatalf("vector %s: %v", v.ID, err)
			}
			eqHex(t, v.ID, "sv2", sv2[:], v.Expected.Sv2)

			dmk, err := AesCmac(k2, sv2[:])
			if err != nil {
				t.Fatalf("vector %s: %v", v.ID, err)
			}
			eqHex(t, v.ID, "derived_mac_key", dmk, v.Expected.DerivedMacKey)

			full, err := AesCmac(dmk, nil)
			if err != nil {
				t.Fatalf("vector %s: %v", v.ID, err)
			}
			eqHex(t, v.ID, "full_cmac", full, v.Expected.FullCmac)

			ok, err := VerifySunMac(k2, p.UID[:], p.CounterBytes[:],
				mustUnhex(t, v.Input.C, "c", v.ID))
			if err != nil {
				t.Fatalf("vector %s: %v", v.ID, err)
			}
			if !ok {
				t.Errorf("vector %s: c=%s not verified", v.ID, v.Input.C)
			}
		}
		if negatives != 3 {
			t.Fatalf("expected 3 negative sdm_full vectors, got %d", negatives)
		}
	})
}
