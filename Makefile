GO ?= go

TOOLS = subdominer urleech probator

.PHONY: all build install vet fmt tidy clean

all: build

build:
	@mkdir -p bin
	@for tool in $(TOOLS); do \
		echo "==> Building $$tool"; \
		$(GO) build -o bin/$$tool ./$$tool/cmd/$$tool || exit 1; \
	done

install:
	@for tool in $(TOOLS); do \
		echo "==> Installing $$tool"; \
		$(GO) install ./$$tool/cmd/$$tool || exit 1; \
	done

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf bin/
