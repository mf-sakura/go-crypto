package main

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestSumSha256(t *testing.T) {
	type args struct {
		message []byte
	}
	// Calculated by other program
	wantBytes, err := hex.DecodeString("4f9c3633e8859bbe74114c4f82aa23ada90dc9a7b59643fd36451239ee1163ea")
	if err != nil {
		t.Fatalf("failed to decode hex string. error:%v", err)
	}
	var want32Bytes [32]byte
	copy(want32Bytes[:], wantBytes[:32])
	tests := []struct {
		name string
		args args
		want [32]byte
	}{
		{
			name: "normal",
			args: args{[]byte("this is test")},
			want: want32Bytes,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SumSha256(tt.args.message); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SumSha256() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Benchmark_SumSha256(b *testing.B) {
	// Benchmark_SumSha256-8   	 5000000	       254 ns/op	       0 B/op	       0 allocs/op
	input := []byte("this is test")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SumSha256(input)
	}
}
