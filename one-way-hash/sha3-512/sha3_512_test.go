package main

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestSumSha3_512(t *testing.T) {
	type args struct {
		message []byte
	}
	// Calculated by other program
	wantBytes, err := hex.DecodeString("962725b95bb275938cb3af6854a13896d3f9a57e452863cea2e918dbae1023a77f2c4373400147d51dc37b9c4e94ec5a93ab0eb70b9723b7d19f998d002a4f9e")
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
			if got := SumSha3_512(tt.args.message); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SumSha512() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Benchmark_SumSha3_512(b *testing.B) {
	// Benchmark_SumSha3_512-8   	 2000000	       920 ns/op	    1024 B/op	       4 allocs/op
	input := []byte("this is test")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SumSha3_512(input)
	}
}
