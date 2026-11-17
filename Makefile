COMPONENT = cpln-audit-shipper
TAG       ?= v1.0.0
ORG       ?=

.PHONY: test build cpln-image

test:
	go vet ./...
	go test -race -count=1 ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(TAG)" -o bin/$(COMPONENT) .

# Builds into a Control Plane org's private registry, for testing before a release: make cpln-image ORG=my-org
cpln-image:
	cpln image build --org $(ORG) --name $(COMPONENT):$(TAG) --dockerfile Dockerfile --dir . --push
