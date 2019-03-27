package main

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestSumSha512(t *testing.T) {
	type args struct {
		message []byte
	}
	// Calculated by other program
	wantBytes, err := hex.DecodeString("a9932879779a505320549ca1f0c321ca45262956c07cd57f4de5c8faecc87deca68afbb826f35e9a44d47da0820d74b86a81804365219edd2e8aaac166654644")
	if err != nil {
		t.Fatalf("failed to decode hex string. error:%v", err)
	}
	var want64Bytes [64]byte
	copy(want64Bytes[:], wantBytes[:64])
	tests := []struct {
		name string
		args args
		want [64]byte
	}{
		{
			name: "normal",
			args: args{[]byte("this is test")},
			want: want64Bytes,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SumSha512(tt.args.message); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SumSha512() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Benchmark_SumSha512(b *testing.B) {
	// Benchmark_SumSha512-8   	 5000000	       358 ns/op	       0 B/op	       0 allocs/op
	input := []byte("this is test")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SumSha512(input)
	}
}
