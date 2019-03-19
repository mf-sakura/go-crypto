package main

import (
	"crypto/rsa"
	"reflect"
	"testing"
)

func TestEncrypt(t *testing.T) {
	type args struct {
		publicKey *rsa.PublicKey
		plainText []byte
		label     []byte
	}
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("failed to create private key.error:%v", err)
		return
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Normal",
			args: args{
				publicKey: &privateKey.PublicKey,
				plainText: []byte("gioahgfpaeb"),
			},
		},
		{
			name: "Public Key is nil",
			args: args{
				publicKey: &privateKey.PublicKey,
				plainText: []byte("gioahgfpaeb"),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Encrypt(tt.args.publicKey, tt.args.plainText, tt.args.label)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Benchmark_Encrypt(b *testing.B) {
	// Benchmark_Encrypt-8   	   20000	     75467 ns/op	   13694 B/op	      34 allocs/op
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		b.Fatalf("failed to create private key")
		return
	}
	publicKey := &privateKey.PublicKey
	defaultPlainText := []byte("hfgiaeohfgio")
	defaultLabel := []byte("test")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(publicKey, defaultPlainText, defaultLabel)
	}
}

func TestDecrypt(t *testing.T) {
	type args struct {
		privateKey *rsa.PrivateKey
		cipherText []byte
		label      []byte
	}
	defaultPlainText := "aaaaa"
	defaultLabel := "test"
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("failed to create private key.error:%v", err)
		return
	}
	cipherText, err := Encrypt(&privateKey.PublicKey, []byte(defaultPlainText), []byte(defaultLabel))
	if err != nil {
		t.Fatalf("failed to encrypt.error:%v", err)
		return
	}
	tests := []struct {
		name      string
		args      args
		want      []byte
		wantErr   bool
		wantPanic bool
	}{
		{
			name: "Normal",
			args: args{
				privateKey: privateKey,
				cipherText: cipherText,
				label:      []byte(defaultLabel),
			},
			want: []byte(defaultPlainText),
		},
		{
			name: "Private Key is nil",
			args: args{
				privateKey: nil,
				cipherText: cipherText,
				label:      []byte(defaultLabel),
			},
			wantPanic: true,
		},
		{
			name: "diffrent label",
			args: args{
				privateKey: privateKey,
				cipherText: cipherText,
				label:      []byte(""),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if err := recover(); (err != nil) != tt.wantPanic {
					t.Errorf("Decrypt() panic. error = %v, wantPanic %v", err, tt.wantPanic)
					return
				}
			}()

			got, err := Decrypt(tt.args.privateKey, tt.args.cipherText, tt.args.label)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Benchmark_Decrypt(b *testing.B) {
	// Benchmark_Decrypt-8   	    1000	   2131413 ns/op	   36391 B/op	     125 allocs/op
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		b.Fatalf("failed to create private key.error:%v", err)
		return
	}
	publicKey := &privateKey.PublicKey
	defaultPlainText := []byte("hfgiaeohfgio")
	defaultLabel := []byte("test")
	cipherText, err := Encrypt(publicKey, defaultPlainText, defaultLabel)
	if err != nil {
		b.Fatalf("failed to encrypt.error:%v", err)
		return
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(privateKey, cipherText, defaultLabel)
	}
}
