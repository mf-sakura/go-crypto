package main

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestCreateHMAC(t *testing.T) {
	type args struct {
		message []byte
		key     []byte
	}
	wantBytes, err := hex.DecodeString("b6544000469390bc83738ea51827c11b7c24136c925c7dbb371984cb32194f50")
	if err != nil {
		t.Fatalf("failed to decode hex string. error:%v", err)
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "normal",
			args: args{
				message: []byte("this is test"),
				key:     []byte("key"),
			},
			want: wantBytes,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CreateHMAC(tt.args.message, tt.args.key); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateHMAC() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Benchmark_CreateHMAC(b *testing.B) {
	// Benchmark_CreateHMAC-8   	 1000000	      1371 ns/op	     512 B/op	       6 allocs/op
	message := []byte("this is test")
	key := []byte("key")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CreateHMAC(message, key)
	}
}

func TestVerifyHMAC(t *testing.T) {
	type args struct {
		message    []byte
		key        []byte
		actualHMAC []byte
	}
	message := []byte("this is test")
	key := []byte("key")
	wantBytes, err := hex.DecodeString("b6544000469390bc83738ea51827c11b7c24136c925c7dbb371984cb32194f50")
	if err != nil {
		t.Fatalf("failed to decode hex string. error:%v", err)
	}
	wrongHMAC := CreateHMAC(message, []byte("wrong key"))
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "normal",
			args: args{
				message:    message,
				key:        key,
				actualHMAC: wantBytes,
			},
			want: true,
		},
		{
			name: "wrong",
			args: args{
				message:    message,
				key:        key,
				actualHMAC: wrongHMAC,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyHMAC(tt.args.message, tt.args.key, tt.args.actualHMAC); got != tt.want {
				t.Errorf("VerifyHMAC() = %v, want %v", got, tt.want)
			}
		})
	}
}
func Benchmark_VerifyHMAC(b *testing.B) {
	// Benchmark_VerifyHMAC-8   	 1000000	      1393 ns/op	     512 B/op	       6 allocs/op
	message := []byte("this is test")
	key := []byte("key")
	want := CreateHMAC(message, key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyHMAC(message, key, want)
	}
}

func Benchmark_VerifyWrongHMAC(b *testing.B) {
	// Benchmark_VerifyWrongHMAC-8   	 1000000	      1371 ns/op	     512 B/op	       6 allocs/op
	message := []byte("this is test")
	key := []byte("key")
	wrongKey := []byte("wrong key")
	wrongHMAC := CreateHMAC(message, wrongKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyHMAC(message, key, wrongHMAC)
	}
}
