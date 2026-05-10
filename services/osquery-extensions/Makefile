BINARY     := aisoc-extension
MODULE     := github.com/beenuar/aisoc/osquery-extensions
GOFLAGS    := -trimpath -ldflags "-s -w"
PLATFORMS  := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# ─── default target ──────────────────────────────────────────────────────────
.PHONY: build
build:
	go build $(GOFLAGS) -o dist/$(BINARY) .

# ─── run unit tests ──────────────────────────────────────────────────────────
.PHONY: test
test:
	go test -race -count=1 ./...

# ─── cross-platform release builds ───────────────────────────────────────────
.PHONY: release
release:
	@mkdir -p dist
	$(foreach PLATFORM,$(PLATFORMS), \
		$(eval GOOS   := $(word 1,$(subst /, ,$(PLATFORM)))) \
		$(eval GOARCH := $(word 2,$(subst /, ,$(PLATFORM)))) \
		$(eval SUFFIX := $(if $(filter windows,$(GOOS)),.exe,)) \
		$(eval OUT    := dist/$(BINARY)-$(GOOS)-$(GOARCH)$(SUFFIX)) \
		GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GOFLAGS) -o $(OUT) . ; \
	)

# ─── tidy / lint ─────────────────────────────────────────────────────────────
.PHONY: tidy vet
tidy:
	go mod tidy

vet:
	go vet ./...

# ─── clean ───────────────────────────────────────────────────────────────────
.PHONY: clean
clean:
	rm -rf dist/
