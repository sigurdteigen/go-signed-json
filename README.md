# go-signed-json

Sign arbitrary JSON messages using the BLS signature scheme.

The [BLS signature scheme](https://en.wikipedia.org/wiki/Boneh%E2%80%93Lynn%E2%80%93Shacham) allows for signing messages using relatively short
signatures, as well as aggregating signatures for multiple messages. This means that a third-party can aggregate multiple signed messages into a
single message with a single short signature. This requires all messages to be signed with the same private key. [Internet-Draft](https://tools.ietf.org/html/draft-boneh-bls-signature-00) | [Short signatures from the Weil pairing](https://www.iacr.org/archive/asiacrypt2001/22480516.pdf)

This small library defines a signed JSON frame format and abstracts away most of the [crypto](https://github.com/phoreproject/bls). It contains only two fields: `m` must be a JSON array and `s` provides the signature.

**Disclaimer**: This is an amateur crypto project. Use this code in production at your own risk.

```json
{
  "m": ["hello, world!", 42],
  "s": "gR3/kthqMpdWCzxPiKzLxpJ5SCiaZj1aVOt1XRxHfKeNqBZSAjRnZAgXU3I2LdwW"
}
```

# Usage
```go
sk, pk, err := NewKeyPair(rand.Reader)

b, err := Marshal(sk, []json.RawMessage{
	json.RawMessage(`"hello, world!"`),
	json.RawMessage(`42`),
})

m, err := Unmarshal(pk, b)
```

###

