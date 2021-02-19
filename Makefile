GO ?=					$(shell which go)

GO_PKGS ?= 				$(shell $(GO) list ./...)

GO_TEST_PKGS ?= 		$(shell test -f go.mod && $(GO) list -f \
							'{{ if or .TestGoFiles .XTestGoFiles }}{{ .ImportPath }}{{ end }}' \
							$(GO_PKGS))

GO_TEST_TIMEOUT ?= 		15s

GO_BENCH=go test -bench=. -benchmem

all: test

test:
	$(GO) test                      \
		-race                       \
		-timeout $(GO_TEST_TIMEOUT) \
		$(GO_TEST_PKGS)

#XXX: ugly
benchmark:
	$(GO_BENCH)
	cd rfc3164 && $(GO_BENCH)
	cd rfc5424 && $(GO_BENCH)

lint:
	golangci-lint run ./...
