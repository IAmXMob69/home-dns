# go/

Go builds of the stack's scripts. Each script runs `go/bin/<tool>` when it exists,
else its own shell or Python body. The tool list is in the main [README](../README.md#go-tools).

Build: `make` here, or `make -C go` from the top (vet, test, build; niced, 2 cores). Needs Go 1.26+.
Exporter image: `make image`, or let `docker compose --profile monitoring up -d` build it.
Rollback: `PIHOLE_NO_GO=1 ./<script>` for one run, or `make clean`.
