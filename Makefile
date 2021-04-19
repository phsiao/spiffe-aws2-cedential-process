
all: fmt tidy vet

fmt:
	@go fmt ./...

vet:
	@go vet ./...

tidy:
	@go mod tidy

.PHONY: all fmt tidy vet