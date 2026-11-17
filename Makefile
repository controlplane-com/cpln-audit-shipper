REGISTRY  = ghcr.io/controlplane-com
COMPONENT = cpln-audit-shipper
IMAGE     = cpln-build/$(COMPONENT)
TAG       ?= v1.1.1
ORG       ?=

.PHONY: test build push-image cpln-image

test:
	go vet ./...
	go test -race -count=1 ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(TAG)" -o bin/$(COMPONENT) .

push-image:
	docker buildx build --push --platform linux/amd64,linux/arm64 -t \
		$(REGISTRY)/$(IMAGE):$(TAG) \
		--build-arg IMAGE_VERSION=$(TAG) \
		.

# Builds into a Control Plane org's private registry, for testing before a release: make cpln-image ORG=my-org
cpln-image:
	cpln image build --org $(ORG) --name $(COMPONENT):$(TAG) --dockerfile Dockerfile --dir . --push
