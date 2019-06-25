PACKAGES=$(shell glide novendor)

builddir := build

$(info builddir ${builddir})

${builddir}:
	mkdir -p $(builddir)

.PHONY: bins
bins: install_ci
	go build -o ${builddir}/arachned github.com/uber/arachne/arachned/

all: bins

clean:
	rm -f ${builddir}/*


.PHONY: lint
lint:
	go vet $(PACKAGES)
	golint $(PACKAGES)

.PHONY: test
test: lint install_ci
	find . -type f -name '*.go' | xargs golint
	go test $(PACKAGES)

.PHONY: vendor
vendor: glide.lock
	glide install

.PHONY: install_ci
install_ci:
	glide --version || go get -u -f github.com/Masterminds/glide
	make vendor
	go get -u golang.org/x/lint/golint
