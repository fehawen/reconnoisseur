BINARY := subdominer
CMD := ./cmd/subdominer
GO ?= go
LDFLAGS :=

.DEFAULT_GOAL := build

.PHONY: build
build:
	$(GO) build -ldflags '$(LDFLAGS)' -o $(BINARY) $(CMD)

.PHONY: install
install:
	$(GO) install -ldflags '$(LDFLAGS)' $(CMD)

.PHONY: test
test:
	$(GO) test ./...

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: check
check: test vet

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: clean
clean:
	rm -f $(BINARY)
