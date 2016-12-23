BENCH_FLAGS ?= -cpuprofile=cpu.pprof -memprofile=mem.pprof -benchmem
PKGS ?= $(shell glide novendor)
# Many Go tools take file globs or directories as arguments instead of packages.
PKG_FILES ?= $(shell find . -name '*.go')

# The linting tools evolve with each Go version, so run them only on the latest
# stable release.
GO_VERSION := $(shell go version | cut -d " " -f 3)
GO_MINOR_VERSION := $(word 2,$(subst ., ,$(GO_VERSION)))
LINTABLE_MINOR_VERSIONS := 7
ifneq ($(filter $(LINTABLE_MINOR_VERSIONS),$(GO_MINOR_VERSION)),)
SHOULD_LINT := true
endif

builddir := build

$(info builddir ${builddir})

${builddir}:
	mkdir -p $(builddir)

.PHONY: bins
bins:
	go build -o ${builddir}/arachne-daemon github.com/uber/arachne/daemon/

all: bins

clean:
	rm -f ${builddir}/*

vendor: glide.lock
	glide install

.PHONY: install_ci
install_ci:
	@echo "Installing Glide and locked dependencies..."
	glide --version || go get -u -f github.com/Masterminds/glide
	make vendor
ifdef SHOULD_LINT
	@echo "Installing golint..."
	go get -u -f github.com/golang/lint/golint
else
	@echo "Not installing golint, since we don't expect to lint on" $(GO_VERSION)
endif

# Disable printf-like invocation checking due to testify.assert.Error()
VET_RULES := -printf=false

.PHONY: test
test:
	@rm -rf vendor
ifdef SHOULD_LINT
	@rm -rf lint.log
	@echo "Checking formatting..."
	@gofmt -d -s $(PKG_FILES) 2>&1 | tee lint.log
	@echo "Checking vet..."
	@$(foreach dir,$(PKG_FILES),go tool vet $(VET_RULES) $(dir) 2>&1 | tee -a lint.log;)
	@echo "Checking lint..."
	@$(foreach dir,$(PKGS),golint $(dir) 2>&1 | tee -a lint.log;)
	@echo "Checking for unresolved FIXMEs..."
	@git grep -i fixme | grep -v -e vendor -e Makefile | tee -a lint.log
	@[ ! -s lint.log ]
else
	@echo "Skipping linters on" $(GO_VERSION)
endif
	@echo "Testing..."
	@go test -i $(PKGS)
	@go test -race $(PKGS)

.PHONY: bench
BENCH ?= .
bench:
	@$(foreach pkg,$(PKGS),go test -bench=$(BENCH) -run="^$$" $(BENCH_FLAGS) $(pkg);)
