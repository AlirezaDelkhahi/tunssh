VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0)
CLEAN_VERSION := $(patsubst v%,%,$(VERSION))
ARCH_VERSION := $(subst -,_,$(CLEAN_VERSION))
GOARCH ?= $(shell go env GOARCH)
WIN_GOARCH ?= amd64
DIST_DIR ?= dist
BIN_PATH ?= bin/tunssh

.PHONY: frontend-build test vet build-linux package-linux build-windows clean

frontend-build:
	cd frontend && ([ -d node_modules ] || npm install) && npm run build

test:
	go test -race -count=1 ./...

vet:
	go vet ./internal/... && go vet -tags webkit2_41 ./...

build-linux: frontend-build
	@mkdir -p bin
	go build -tags "desktop,production,webkit2_41" -ldflags="-s -w" -o $(BIN_PATH) ./cmd/tunssh

package-linux: build-linux
	@command -v nfpm >/dev/null 2>&1 || { \
		echo "Error: nfpm is not installed."; \
		echo "Install it locally with: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"; \
		exit 1; \
	}
	@mkdir -p $(DIST_DIR)
	@set -e; \
	stage_dir=$$(mktemp -d); \
	trap 'rm -rf "$$stage_dir"' EXIT; \
	cp $(BIN_PATH) "$$stage_dir/tunssh"; \
	cp packaging/tunssh.desktop "$$stage_dir/tunssh.desktop"; \
	cp packaging/tunssh.svg "$$stage_dir/tunssh.svg"; \
	tar -C "$$stage_dir" -czf $(DIST_DIR)/tunssh-$(VERSION)-linux-$(GOARCH).tar.gz tunssh tunssh.desktop tunssh.svg
	VERSION=$(CLEAN_VERSION) GOARCH=$(GOARCH) BIN_PATH=$(BIN_PATH) nfpm package -f packaging/nfpm.yaml -p deb -t $(DIST_DIR)/
	VERSION=$(CLEAN_VERSION) GOARCH=$(GOARCH) BIN_PATH=$(BIN_PATH) nfpm package -f packaging/nfpm.yaml -p rpm -t $(DIST_DIR)/
	VERSION=$(ARCH_VERSION) GOARCH=$(GOARCH) BIN_PATH=$(BIN_PATH) nfpm package -f packaging/nfpm.yaml -p archlinux -t $(DIST_DIR)/
	cd $(DIST_DIR) && sha256sum *.tar.gz *.deb *.rpm *.pkg.tar.zst > SHA256SUMS.txt

build-windows: frontend-build
	@mkdir -p bin
	./packaging/fetch-wintun.sh $(WIN_GOARCH) bin
	GOOS=windows GOARCH=$(WIN_GOARCH) CGO_ENABLED=0 go build -tags "desktop,production" -ldflags="-s -w -H windowsgui" -o bin/tunssh.exe ./cmd/tunssh

clean:
	rm -rf bin $(DIST_DIR)
