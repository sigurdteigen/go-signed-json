package signedjson

import (
	"bytes"
	"encoding/json"
	"io"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignSingle(t *testing.T) {
	sk, pk, err := NewKeyPair(rand.New(rand.NewSource(0)))
	require.NoError(t, err)

	b, err := Marshal(sk, []json.RawMessage{json.RawMessage(`"hello, world!"`)})
	require.NoError(t, err)

	require.Equal(t, `{"m":["hello, world!"],"s":"iRjNxGUQ3Lv03tId49A57GQM4l6iCUt55oZ0Y5hksnRM6wj7fat5FKaBE4/AgHXb"}`, string(b))

	m, err := Unmarshal(pk, b)
	require.NoError(t, err)
	require.Equal(t, []json.RawMessage{json.RawMessage(`"hello, world!"`)}, m)
}

func TestSignMulti(t *testing.T) {
	sk, pk, err := NewKeyPair(rand.New(rand.NewSource(0)))
	require.NoError(t, err)

	msgs := []json.RawMessage{
		json.RawMessage(`"hello, world!"`),
		json.RawMessage(`42`),
	}

	b, err := Marshal(sk, msgs)
	require.NoError(t, err)

	require.Equal(t, `{"m":["hello, world!",42],"s":"gR3/kthqMpdWCzxPiKzLxpJ5SCiaZj1aVOt1XRxHfKeNqBZSAjRnZAgXU3I2LdwW"}`, string(b))

	m, err := Unmarshal(pk, b)
	require.NoError(t, err)
	require.Equal(t, msgs, m)
}

func TestAggregate(t *testing.T) {
	sk, pk, err := NewKeyPair(rand.New(rand.NewSource(0)))
	require.NoError(t, err)

	msgs := []json.RawMessage{
		json.RawMessage(`"hello, world!"`),
		json.RawMessage(`42`),
	}

	b1, err := Marshal(sk, msgs[:1])
	require.NoError(t, err)

	b2, err := Marshal(sk, msgs[1:])
	require.NoError(t, err)

	agg := bytes.Buffer{}
	require.NoError(t, Aggregate(&agg, []io.Reader{
		bytes.NewBuffer(b1),
		bytes.NewBuffer(b2),
	}))

	zz := agg.String()
	require.Equal(t, `{"m":["hello, world!",42],"s":"gR3/kthqMpdWCzxPiKzLxpJ5SCiaZj1aVOt1XRxHfKeNqBZSAjRnZAgXU3I2LdwW"}`, zz)

	m, err := Unmarshal(pk, []byte(zz))
	require.NoError(t, err)
	require.Equal(t, msgs, m)
}
