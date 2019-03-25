package main

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestSign(t *testing.T) {
	type args struct {
		message    []byte
		privateKey *rsa.PrivateKey
		option     *rsa.PSSOptions
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
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
			_, err := Sign(tt.args.message, tt.args.privateKey, tt.args.option)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Benchmark_Sign(b *testing.B) {
	// Benchmark_Sign-8   	    1000	   2193051 ns/op	   49394 B/op	     151 allocs/op
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("failed to create private key")
		return
	}
	message := []byte("this is test")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sign(message, privateKey, nil)
	}
}

func TestVerify(t *testing.T) {
	type args struct {
		message   []byte
		sig       []byte
		publicKey *rsa.PublicKey
		option    *rsa.PSSOptions
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to create private key.error:%v", err)
		return
	}
	message := []byte("this is test")
	sig, err := Sign(message, privateKey, nil)
	if err != nil {
		t.Fatalf("failed to sign. error:%v", err)
		return
	}
	tests := []struct {
		name      string
		args      args
		want      bool
		wantErr   bool
		wantPanic bool
	}{
		{
			name: "normal",
			args: args{
				message:   message,
				sig:       sig,
				publicKey: &privateKey.PublicKey,
			},
			want: true,
		},
		{
			name: "salt length is different",
			args: args{
				message:   []byte("this is test"),
				sig:       sig,
				publicKey: &privateKey.PublicKey,
				option:    &rsa.PSSOptions{SaltLength: 10},
			},
			wantErr: true,
		},
		{
			name: "public key is nil",
			args: args{
				message:   message,
				sig:       sig,
				publicKey: nil,
			},
			wantPanic: true,
		},
		{
			name: "signature is nil",
			args: args{
				message:   []byte("this is test"),
				sig:       nil,
				publicKey: &privateKey.PublicKey,
			},
			wantErr: true,
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
			got, err := Verify(tt.args.message, tt.args.sig, tt.args.publicKey, tt.args.option)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Benchmark_Verify_Success(b *testing.B) {
	// Benchmark_Verify_Success-8   	   20000	     75360 ns/op	   13957 B/op	      35 allocs/op
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("failed to create private key")
		return
	}
	message := []byte("this is test")
	sig, err := Sign(message, privateKey, nil)
	if err != nil {
		b.Fatalf("failed to sign")
		return
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(message, sig, &privateKey.PublicKey, nil)
	}
}

func Benchmark_Verify_Failed(b *testing.B) {
	// Benchmark_Verify_Failed-8   	   20000	     74604 ns/op	   13957 B/op	      35 allocs/op
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("failed to create private key")
		return
	}
	message := []byte("this is test")
	wrongMessage := []byte("this is failure case")
	sig, err := Sign(wrongMessage, privateKey, nil)
	if err != nil {
		b.Fatalf("failed to sign")
		return
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(message, sig, &privateKey.PublicKey, nil)
	}
}
