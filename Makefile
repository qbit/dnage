build:
	go build

check:
	go vet
	gosec .

test: check
	go test
