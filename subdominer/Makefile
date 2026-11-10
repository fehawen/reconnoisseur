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

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: clean
clean:
	rm -f $(BINARY)
