PACKAGES=$(shell glide novendor)

builddir := build

$(info builddir ${builddir})

${builddir}:
	mkdir -p $(builddir)

.PHONY: bins
bins:
	go build -o ${builddir}/arachned github.com/uber/arachne/arachned/

all: bins

clean:
	rm -f ${builddir}/*


.PHONY: lint
lint:
	go vet $(PACKAGES)

.PHONY: test
test: check-license lint
	find . -type f -name '*.go' | xargs golint
	go test $(PACKAGES)

.PHONY: vendor
vendor: glide.lock
	glide install

.PHONY: install_ci
install_ci:
	glide --version || go get -u -f github.com/Masterminds/glide
	make vendor
	go get -u -f github.com/golang/lint/golint

vendor/github.com/uber/uber-licence: vendor
	[ -d vendor/github.com/uber/uber-licence ] || glide install

vendor/github.com/uber/uber-licence/node_modules: vendor/github.com/uber/uber-licence
	cd vendor/github.com/uber/uber-licence && npm install

.PHONY: check-license
check-license: vendor/github.com/uber/uber-licence/node_modules
	./vendor/github.com/uber/uber-licence/bin/licence --dry --file '*.go'

.PHONY: add-license
add-license: vendor/github.com/uber/uber-licence/node_modules
	./vendor/github.com/uber/uber-licence/bin/licence --verbose --file '*.go'
