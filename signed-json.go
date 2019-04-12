package signedjson

import (
	"bytes"
	"encoding/json"
	"io"

	jsoniter "github.com/json-iterator/go"
	"github.com/phoreproject/bls"
)

// Encoder serializes and signes arbitary JSON messages into a single signed frame
type Encoder interface {
	Encode(messages []json.RawMessage) error
}

// Decoder deserializes messages and verifies the signature of a single signed frame
type Decoder interface {
	Decode() ([]json.RawMessage, error)
}

// NewEncoder creates a new encoder writing signed frames to w.
// Nothing is buffered.
func NewEncoder(w io.Writer, secretKey [32]byte) Encoder {
	sk := bls.DeserializeSecretKey(secretKey)

	return &encoder{
		w:  w,
		sk: sk,
	}
}

// NewDecoder creates a new decoder reading a signed frame from r and verifies the signature
func NewDecoder(r io.Reader, publicKey [96]byte) (Decoder, error) {
	pk, err := bls.DeserializePublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return &decoder{
		r:  r,
		pk: pk,
	}, nil
}

// Encode encodes an array of arbitrary JSON messages and signs the result.
func (enc *encoder) Encode(messages []json.RawMessage) error {
	sigs := make([]*bls.Signature, len(messages))
	for i := 0; i < len(messages); i++ {
		sigs[i] = bls.Sign(messages[i], enc.sk, 0)
	}

	sig := bls.AggregateSignatures(sigs)

	enc.w.Write([]byte(`{"m":[`))
	enc.w.Write(messages[0])
	for i := 1; i < len(messages); i++ {
		enc.w.Write([]byte{','})
		enc.w.Write(messages[i])
	}
	enc.w.Write([]byte(`],"s":"`))
	enc.w.Write(marshalSignature(sig))
	enc.w.Write([]byte(`"}`))

	return nil
}

// Decode deserializes a signed frame, verifies the signature and returns the containing messages
func (dec *decoder) Decode() ([]json.RawMessage, error) {
	v, err := read(dec.r)
	if err != nil {
		return nil, err
	}

	if err := v.verify(dec.pk); err != nil {
		return nil, err
	}

	return v.messages, nil
}

// Marshal is a convenience function using an Encoder to write and sign a frame
func Marshal(secretKey [32]byte, messages []json.RawMessage) ([]byte, error) {
	buf := bytes.Buffer{}
	enc := NewEncoder(&buf, secretKey)
	if err := enc.Encode(messages); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Unmarshal is a convenience function using a Decoder to read and verify a frame
func Unmarshal(publicKey [96]byte, b []byte) ([]json.RawMessage, error) {
	dec, err := NewDecoder(bytes.NewReader(b), publicKey)
	if err != nil {
		return nil, err
	}

	return dec.Decode()
}

// Aggregate reads a list of frames from rs and writes a single new frame to w containing all the messages read
// from rs. The signatures of all the input frames are then aggregated (combined) into a single signature for the
// output frame.
// This operation does not require keys and may be done by a third-party.
func Aggregate(w io.Writer, rs []io.Reader) error {
	var sigs []*bls.Signature

	w.Write([]byte(`{"m":[`))
	first := true
	for _, r := range rs {
		sig, err := readcb(r, func(it *jsoniter.Iterator) {
			if first {
				first = false
			} else {
				w.Write([]byte{','})
			}

			w.Write(it.SkipAndReturnBytes())
		})
		if err != nil {
			return err
		}

		sigs = append(sigs, sig)
	}

	w.Write([]byte(`],"s":"`))
	w.Write(marshalSignature(bls.AggregateSignatures(sigs)))
	_, err := w.Write([]byte(`"}`))
	return err
}

// NewKeyPair generates a new keypair that may be used to sign and verify frames using the Encoder and Decoder.
func NewKeyPair(rand io.Reader) ([32]byte, [96]byte, error) {
	sk, err := bls.RandKey(rand)
	if err != nil {
		return [32]byte{}, [96]byte{}, err
	}

	pk := bls.PrivToPub(sk)
	return sk.Serialize(), pk.Serialize(), nil
}
