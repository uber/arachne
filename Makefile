PACKAGES=$(shell glide novendor)

builddir := build

$(info builddir ${builddir})

${builddir}:
	mkdir -p $(builddir)

bins: install_ci
	go build -o ${builddir}/arachned github.com/uber/arachne/arachned/

all: bins

clean:
	rm -f ${builddir}/*

FILTER := grep -v -e '_string.go' -e '/gen-go/' -e '/mocks/' -e 'vendor/'
lint:
	@echo "Running golint"
	-golint $(ALL_PKGS) | $(FILTER) | tee lint.log
	@echo "Running go vet"
	-go vet $(ALL_PKGS) 2>&1 | fgrep -v -e "possible formatting directiv" -e "exit status" | tee -a lint.log
	@echo "Verifying files are gofmt'd"
	-gofmt -l . | $(FILTER) | tee -a lint.log
	@echo "Checking for unresolved FIXMEs"
	-git grep -i -n fixme | $(FILTER) | grep -v -e Makefile | tee -a lint.log
	@[ ! -s lint.log ]

test: lint install_ci
	find . -type f -name '*.go' | xargs golint
	go test $(PACKAGES)

vendor: glide.lock
	glide install

install_ci:
	glide --version || go get -u -f github.com/Masterminds/glide
	make vendor
	go get -u golang.org/x/lint/golint

.PHONY: bins test vendor install_ci lint
