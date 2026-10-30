# Pi-hole stack tools in Go. Builds are niced and limited to 2 cores.
GO      ?= go
NICE    := nice -n19 ionice -c3
export GOMAXPROCS := 2
export CGO_ENABLED := 0
GOFLAGS_BUILD := -p 2 -trimpath -ldflags "-s -w"
TOOLS := pihole-install geolock-apply malice-ip-apply pihole-groups pihole-exporter refresh-dot-cert \
	apply-stack backup cleanup debug-window-off dns-probe expose-lan fix-pihole harden healthcheck import-lists import-webpwnized-lists install-privacy-shield join-tailnet publish-tailscale-dns rollback-dns setup-tailscale-privileged status update-gravity update-pihole watchdog indic-idn-guard
IMAGE   ?= pihole-pihole-exporter

.PHONY: all build test vet clean image
all: vet test build

build: $(addprefix bin/,$(TOOLS))

bin/%: $(shell find cmd internal -name '*.go') go.mod go.sum
	$(NICE) $(GO) build $(GOFLAGS_BUILD) -o $@ ./cmd/$*

vet:
	$(NICE) $(GO) vet -p 2 ./...

test:
	$(NICE) $(GO) test -p 2 ./...

# Exporter image: static binary on scratch (no Python, no pip).
image:
	$(NICE) docker build -f Dockerfile.exporter -t $(IMAGE) .

clean:
	rm -rf bin
