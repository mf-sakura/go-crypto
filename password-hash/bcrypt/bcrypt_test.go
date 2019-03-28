package main

import (
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestGeneratePasswordHash(t *testing.T) {
	type args struct {
		password []byte
		cost     int
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "normal",
			args: args{
				password: []byte("aaa"),
				cost:     0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GeneratePasswordHash(tt.args.password, tt.args.cost)
			if (err != nil) != tt.wantErr {
				t.Errorf("GeneratePasswordHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Benchmark_PasswordHash(b *testing.B) {
	// Benchmark_PasswordHash/Cost_is_4-8         	    1000	   1232860 ns/op	    5162 B/op	      11 allocs/op
	// Benchmark_PasswordHash/Cost_is_5-8         	    1000	   2382698 ns/op	    5162 B/op	      11 allocs/op
	// Benchmark_PasswordHash/Cost_is_6-8         	     300	   4665631 ns/op	    5164 B/op	      11 allocs/op
	// Benchmark_PasswordHash/Cost_is_7-8         	     200	   9311593 ns/op	    5166 B/op	      11 allocs/op
	// Benchmark_PasswordHash/Cost_is_8-8         	     100	  18818327 ns/op	    5172 B/op	      11 allocs/op
	// Benchmark_PasswordHash/Cost_is_9-8         	      50	  36560429 ns/op	    5184 B/op	      11 allocs/op
	// Benchmark_PasswordHash/Cost_is_10-8        	      20	  75307879 ns/op	    5222 B/op	      11 allocs/op
	// Benchmark_PasswordHash/Cost_is_11-8        	      10	 146922213 ns/op	    5284 B/op	      11 allocs/op
	// Benchmark_PasswordHash/Cost_is_12-8        	       5	 291566438 ns/op	    5406 B/op	      11 allocs/op
	// Benchmark_PasswordHash/Cost_is_13-8        	       2	 592188337 ns/op	    5780 B/op	      13 allocs/op
	// Benchmark_PasswordHash/Cost_is_14-8        	       1	1185157799 ns/op	    6392 B/op	      15 allocs/op
	// Benchmark_PasswordHash/Cost_is_15-8        	       1	2372851798 ns/op	    6392 B/op	      15 allocs/op
	// Benchmark_PasswordHash/Cost_is_16-8        	       1	4715214426 ns/op	    6392 B/op	      15 allocs/op
	// Benchmark_PasswordHash/Cost_is_17-8        	       1	9602356808 ns/op	    6392 B/op	      15 allocs/op
	// Benchmark_PasswordHash/Cost_is_18-8        	       1	19564616874 ns/op	    6392 B/op	      15 allocs/op
	// Benchmark_PasswordHash/Cost_is_19-8        	       1	39022871665 ns/op	    6392 B/op	      15 allocs/op
	// Benchmark_PasswordHash/Cost_is_20-8        	       1	77482482816 ns/op	    6392 B/op	      15 allocs/op
	// Benchmark_PasswordHash/Cost_is_21-8        	       1	158957315995 ns/op	    6408 B/op	      15 allocs/op
	password := []byte("test")
	b.ResetTimer()
	for j := bcrypt.MinCost; j <= bcrypt.MaxCost; j++ {
		b.Run(fmt.Sprintf("Cost is %d", j), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				GeneratePasswordHash(password, j)
			}
		})
	}
}

func TestCheckPasswordHash(t *testing.T) {
	type args struct {
		password []byte
		hashed   []byte
	}
	passwordBytes, err := hex.DecodeString("2432612431302455546937465a4f35363373487175506a75523477426570646e544e2f5862717162494357684a3064503657796357473432464e5857")
	if err != nil {
		t.Fatal(" hex.DecodeString failed ")
	}

	passwordBytes2, err := hex.DecodeString("2432612431302472466e32434f477662486838686e71596836555a502e4438462f4169572f414d586f4f6c306632446175505a317957486c7035324b")
	if err != nil {
		t.Fatal(" hex.DecodeString failed ")
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "normal",
			args: args{
				password: []byte("aaa"),
				hashed:   passwordBytes,
			},
		},
		{
			name: "normal2 another hash corresponding to same password",
			args: args{
				password: []byte("aaa"),
				hashed:   passwordBytes2,
			},
		},
		{
			name: "password is wrong",
			args: args{
				password: []byte("abc"),
				hashed:   passwordBytes,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckPasswordHash(tt.args.password, tt.args.hashed); (err != nil) != tt.wantErr {
				t.Errorf("CheckPasswordHash() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
func Benchmark_CheckPasswordHash(b *testing.B) {
	// Benchmark_CheckPasswordHash/Cost_is_4-8         	    1000	   1288953 ns/op	    5258 B/op	      15 allocs/op
	// Benchmark_CheckPasswordHash/Cost_is_5-8         	     500	   2655975 ns/op	    5258 B/op	      15 allocs/op
	// Benchmark_CheckPasswordHash/Cost_is_6-8         	     300	   4942696 ns/op	    5260 B/op	      15 allocs/op
	// Benchmark_CheckPasswordHash/Cost_is_7-8         	     200	   9847396 ns/op	    5262 B/op	      15 allocs/op
	// Benchmark_CheckPasswordHash/Cost_is_8-8         	     100	  19972647 ns/op	    5268 B/op	      15 allocs/op
	// Benchmark_CheckPasswordHash/Cost_is_9-8         	      30	  39810823 ns/op	    5297 B/op	      15 allocs/op
	// Benchmark_CheckPasswordHash/Cost_is_10-8        	      20	  79806258 ns/op	    5318 B/op	      15 allocs/op
	// Benchmark_CheckPasswordHash/Cost_is_11-8        	      10	 158170702 ns/op	    5380 B/op	      15 allocs/op
	// Benchmark_CheckPasswordHash/Cost_is_12-8        	       5	 312520948 ns/op	    5505 B/op	      15 allocs/op
	// Benchmark_CheckPasswordHash/Cost_is_13-8        	       2	 620418053 ns/op	    5876 B/op	      17 allocs/op
	// Benchmark_CheckPasswordHash/Cost_is_14-8        	       1	1244654539 ns/op	    6504 B/op	      19 allocs/op
	// Benchmark_CheckPasswordHash/Cost_is_15-8        	       1	2495570060 ns/op	    6504 B/op	      19 allocs/op
	// Benchmark_CheckPasswordHash/Cost_is_16-8        	       1	5147497263 ns/op	    6504 B/op	      19 allocs/op
	// Benchmark_CheckPasswordHash/Cost_is_17-8        	       1	10043442105 ns/op	    6504 B/op	      19 allocs/op
	password := []byte("test")
	b.ResetTimer()
	for j := bcrypt.MinCost; j <= bcrypt.MaxCost; j++ {
		hash, err := GeneratePasswordHash(password, j)
		if err != nil {
			b.Fatal("GeneratePasswordHash failed")
		}
		b.Run(fmt.Sprintf("Cost is %d", j), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				CheckPasswordHash(password, hash)
			}
		})
	}
}
