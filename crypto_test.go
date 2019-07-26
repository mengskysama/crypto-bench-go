package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rc4"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

const bSize = 4096


func BenchmarkRC4(b *testing.B) {
	key := make([]byte, 16)
	rc4, err := rc4.NewCipher(key)
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, bSize)
	b.SetBytes(bSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rc4.XORKeyStream(data, data)
	}
}

func BenchmarkCacha20Poly1305(b *testing.B) {
	key := make([]byte, chacha20poly1305.KeySize)
	nonce := make([]byte, chacha20poly1305.NonceSize)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, bSize)
	b.SetBytes(bSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aead.Seal(nil, nonce, data, []byte{})
	}
}

func BenchmarkAES128GCM(b *testing.B) {
	benchmarkAES(b, 128/8)
}

func BenchmarkAES256CM(b *testing.B) {
	benchmarkAES(b, 256/8)
}

func benchmarkAES(b *testing.B, keysize int) {
	key := make([]byte, keysize)
	nonce := make([]byte, chacha20poly1305.NonceSize)
	aes, err := aes.NewCipher(key)
	if err != nil {
		b.Fatal(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, bSize)
	b.SetBytes(bSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aead.Seal(nil, nonce, data, []byte{})
	}
}
