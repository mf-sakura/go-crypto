package main

import (
	"crypto/ecdsa"
	"math/big"
	"testing"
)

func TestSign(t *testing.T) {
	type args struct {
		message    []byte
		privateKey *ecdsa.PrivateKey
	}
	privateKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to create private key.error:%v", err)
		return
	}
	tests := []struct {
		name      string
		args      args
		wantErr   bool
		wantPanic bool
	}{
		{
			name: "normal",
			args: args{
				message:    []byte("this is test"),
				privateKey: privateKey,
			},
		},
		{
			name: "private key is nil",
			args: args{
				message:    []byte("this is test"),
				privateKey: nil,
			},
			wantPanic: true,
		},
		{
			name: "message is nil",
			args: args{
				message:    nil,
				privateKey: privateKey,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if err := recover(); (err != nil) != tt.wantPanic {
					t.Errorf("Sign() panic. error = %v, wantPanic %v", err, tt.wantPanic)
					return
				}
			}()
			_, _, err := Sign(tt.args.message, tt.args.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Benchmark_Sign(b *testing.B) {
	// Benchmark_Sign-8   	   50000	     34213 ns/op	    2945 B/op	      35 allocs/op
	privateKey, err := GenerateKey()
	if err != nil {
		b.Fatalf("failed to create private key")
		return
	}
	message := []byte("this is test")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sign(message, privateKey)
	}
}

func TestVerify(t *testing.T) {
	type args struct {
		message   []byte
		publicKey *ecdsa.PublicKey
		r         *big.Int
		s         *big.Int
	}
	message := []byte("this is test")
	privateKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to create private key.error:%v", err)
		return
	}
	publicKey := &privateKey.PublicKey

	r, s, err := Sign(message, privateKey)
	if err != nil {
		t.Fatalf("failed to sign.error:%v", err)
		return
	}
	tests := []struct {
		name      string
		args      args
		want      bool
		wantPanic bool
	}{
		{
			name: "normal",
			args: args{
				message:   message,
				publicKey: publicKey,
				r:         r,
				s:         s,
			},
			want: true,
		},
		{
			name: "public key is nil",
			args: args{
				message:   message,
				publicKey: nil,
				r:         r,
				s:         s,
			},
			wantPanic: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if err := recover(); (err != nil) != tt.wantPanic {
					t.Errorf("Verify() panic. error = %v, wantPanic %v", err, tt.wantPanic)
					return
				}
			}()
			if got := Verify(tt.args.message, tt.args.publicKey, tt.args.r, tt.args.s); got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Benchmark_Verify_Success(b *testing.B) {
	// Benchmark_Verify_Success-8   	   10000	    101291 ns/op	    1152 B/op	      18 allocs/op
	privateKey, err := GenerateKey()
	if err != nil {
		b.Fatalf("failed to create private key")
		return
	}
	message := []byte("this is test")
	r, s, err := Sign(message, privateKey)
	if err != nil {
		b.Fatalf("failed to sign")
		return
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(message, &privateKey.PublicKey, r, s)
	}
}

func Benchmark_Verify_Wrong(b *testing.B) {
	// Benchmark_Verify_Wrong-8   	   10000	    104434 ns/op	    1152 B/op	      18 allocs/op
	privateKey, err := GenerateKey()
	if err != nil {
		b.Fatalf("failed to create private key")
		return
	}
	message := []byte("this is test")
	r, s, err := Sign(message, privateKey)
	if err != nil {
		b.Fatalf("failed to sign")
		return
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(message, &privateKey.PublicKey, s, r)
	}
}
