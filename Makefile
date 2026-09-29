# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI catalog characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

BLUE         := $(shell printf "\033[34m")
YELLOW       := $(shell printf "\033[33m")
RED          := $(shell printf "\033[31m")
GREEN        := $(shell printf "\033[32m")
CNone        := $(shell printf "\033[0m")

INFO    = echo ${TIME} ${BLUE}[ .. ]${CNone}
WARN    = echo ${TIME} ${YELLOW}[WARN]${CNone}
ERR     = echo ${TIME} ${RED}[FAIL]${CNone}
OK      = echo ${TIME} ${GREEN}[ OK ]${CNone}
FAIL    = (echo ${TIME} ${RED}[FAIL]${CNone} && false)

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

help: ## Display this concise help, ie only the porcelain target.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

help-all: ## Display all help items, ie including plumbing targets.
	@awk 'BEGIN {FS = ":.*#"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?#/ { printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

proto-gen: ## Generate objects from proto definitions
	@buf generate

##@ Test
.PHONY: test
test:  ## Run tests
	@if ! go test ./... -coverprofile cover.out -v; then \
		$(WARN) "Tests failed"; \
		exit 1; \
	fi ; \
	$(OK) Tests passed

.PHONY: check-opa-version
check-opa-version: ## Check the agent and the API module require the same OPA version
	@graph=$$(go mod graph); \
	agent_opa=$$(awk '$$1 == "github.com/compliance-framework/agent" && $$2 ~ /^github.com\/open-policy-agent\/opa@/ { sub(/.*@/, "", $$2); print $$2 }' <<< "$$graph"); \
	api_opa=$$(awk '$$1 ~ /^github.com\/compliance-framework\/api@/ && $$2 ~ /^github.com\/open-policy-agent\/opa@/ { sub(/.*@/, "", $$2); print $$2 }' <<< "$$graph"); \
	if [ -z "$$agent_opa" ] || [ -z "$$api_opa" ]; then \
		$(ERR) "Could not find the OPA requirement: agent '$$agent_opa', api '$$api_opa'"; \
		exit 1; \
	fi; \
	if [ "$$agent_opa" != "$$api_opa" ]; then \
		$(ERR) "OPA version drift: agent requires $$agent_opa, api requires $$api_opa. Policies must evaluate the same in both."; \
		exit 1; \
	fi; \
	$(OK) "Agent and API both require OPA $$agent_opa"


build: ## Build the project
	@mkdir -p dist
	@go build -o dist/concom main.go

run: ## Run the project	
	@go run main.go agent --config ./.config/config.yaml

