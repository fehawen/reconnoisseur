BINARY := urleech
CMD := ./cmd/urleech
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

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: clean
clean:
	rm -f $(BINARY)
