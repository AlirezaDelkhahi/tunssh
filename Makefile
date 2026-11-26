VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0)
CLEAN_VERSION := $(patsubst v%,%,$(VERSION))
GOARCH ?= $(shell go env GOARCH)
WIN_GOARCH ?= amd64
DIST_DIR ?= dist
BIN_PATH ?= bin/tunssh

.PHONY: frontend-build test vet build-linux package-linux build-windows package-windows build-android-aar build-android package-android clean

define write_dist_checksums
	cd $(DIST_DIR) && { \
		for f in *.tar.gz *.deb *.rpm *.pkg.tar.zst *.zip *.apk; do \
			if [ -e "$$f" ]; then sha256sum "$$f"; fi; \
		done; \
	} > SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS.txt
endef

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
	[ "$(BIN_PATH)" = "bin/tunssh" ] || cp -f "$(BIN_PATH)" bin/tunssh
	for pkg in deb rpm archlinux; do \
		VERSION=$(CLEAN_VERSION) GOARCH=$(GOARCH) nfpm package -f packaging/nfpm.yaml -p "$$pkg" -t $(DIST_DIR)/; \
	done
	$(call write_dist_checksums)

build-windows: frontend-build
	@mkdir -p bin
	@rm -f cmd/tunssh/rsrc_windows_*.syso
	@if command -v go-winres >/dev/null 2>&1; then \
		go-winres make --in packaging/winres/winres.json --out cmd/tunssh/rsrc --arch $(WIN_GOARCH) --product-version $(CLEAN_VERSION) --file-version $(CLEAN_VERSION); \
	else \
		echo "Warning: go-winres not found; building without embedded icon/manifest (go install github.com/tc-hib/go-winres@latest)"; \
	fi
	./packaging/fetch-wintun.sh $(WIN_GOARCH) bin
	GOOS=windows GOARCH=$(WIN_GOARCH) CGO_ENABLED=0 go build -tags "desktop,production" -ldflags="-s -w -H windowsgui" -o bin/tunssh.exe ./cmd/tunssh
	@rm -f cmd/tunssh/rsrc_windows_*.syso

package-windows: build-windows
	@mkdir -p $(DIST_DIR)
	@rm -f $(DIST_DIR)/tunssh-$(VERSION)-windows-$(WIN_GOARCH).zip
	@zip_out="$(abspath $(DIST_DIR))/tunssh-$(VERSION)-windows-$(WIN_GOARCH).zip"; \
	cd bin && if command -v zip >/dev/null 2>&1; then \
		zip -q "$$zip_out" tunssh.exe wintun.dll; \
	else \
		python3 -m zipfile -c "$$zip_out" tunssh.exe wintun.dll; \
	fi
	$(call write_dist_checksums)

build-android-aar:
	./packaging/build-android.sh aar

build-android:
	./packaging/build-android.sh debug

package-android:
	VERSION=$(CLEAN_VERSION) DIST_DIR=$(abspath $(DIST_DIR)) ./packaging/build-android.sh release
	$(call write_dist_checksums)

clean:
	rm -rf bin $(DIST_DIR)
