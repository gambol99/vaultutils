
NAME=vaultutils
AUTHOR ?= gambol99
VETARGS ?= -asmdecl -atomic -bool -buildtags -copylocks -methods -nilfunc -printf -rangeloops -shift -structtags -unsafeptr

.PHONY: test authors changelog

default: test

authors:
	@echo "--> Updating the AUTHORS"
	git log --format='%aN <%aE>' | sort -u > AUTHORS

deps:
	@echo "--> Installing build dependencies"
	go get -d -v ./...
	go get github.com/stretchr/testify/assert

vet:
	@echo "--> Running go tool vet $(VETARGS) ."
	@go tool vet 2>/dev/null ; if [ $$? -eq 3 ]; then \
		go get golang.org/x/tools/cmd/vet; \
	fi
	@go tool vet $(VETARGS) .

format:
	@echo "--> Running go fmt"
	@go fmt $(PACKAGES)

cover:
	@echo "--> Running go cover"
	go list ./... | xargs -n1 go test --cover

test: deps
	@echo "--> Running the tests"
	go test -v
	@$(MAKE) vet
	@$(MAKE) cover

changelog: release
	git log $(shell git tag | tail -n1)..HEAD --no-merges --format=%B > changelog
