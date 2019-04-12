package signedjson

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	jsoniter "github.com/json-iterator/go"
	"github.com/phoreproject/bls"
)

type encoder struct {
	w  io.Writer
	sk *bls.SecretKey
}

type decoder struct {
	r  io.Reader
	pk *bls.PublicKey
}

type jsonbls struct {
	messages  []json.RawMessage
	signature *bls.Signature
}

func marshalSignature(sig *bls.Signature) []byte {
	z := sig.Serialize()
	return []byte(base64.RawStdEncoding.EncodeToString(z[:]))
}

func (v *jsonbls) verify(pk *bls.PublicKey) error {
	msgs := make([][]byte, len(v.messages))
	pks := make([]*bls.PublicKey, len(v.messages))
	for i := 0; i < len(msgs); i++ {
		msgs[i] = v.messages[i]
		pks[i] = pk
	}

	if !v.signature.VerifyAggregate(pks, msgs, 0) {
		return errors.New("signature verification failed")
	}

	return nil
}

func read(r io.Reader) (*jsonbls, error) {
	var v jsonbls
	var err error
	v.signature, err = readcb(r, func(it *jsoniter.Iterator) {
		v.messages = append(v.messages, it.SkipAndReturnBytes())
	})
	return &v, err
}

func readcb(r io.Reader, msgcb func(it *jsoniter.Iterator)) (*bls.Signature, error) {
	var sig *bls.Signature
	if frameiter := jsoniter.Parse(jsoniter.ConfigFastest, r, 1024); !frameiter.ReadObjectCB(func(it *jsoniter.Iterator, key string) bool {
		switch key {
		case "m":
			return it.ReadArrayCB(func(msgit *jsoniter.Iterator) bool {
				msgcb(msgit)
				return true
			})

		case "s":
			var s [48]byte
			base64.RawStdEncoding.Decode(s[:], it.ReadStringAsSlice())
			var err error
			sig, err = bls.DeserializeSignature(s)
			if err != nil {
				it.ReportError("parsing signature", err.Error())
				return false
			}
			return true
		}

		return true
	}) {
		return sig, frameiter.Error
	}

	return sig, nil
}
