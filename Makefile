SHELL += -eu

BLUE  := \033[0;34m
GREEN := \033[0;32m
RED   := \033[0;31m
NC    := \033[0m

DOCKER_ORG_NAME = liblynx
DOCKER_IMAGE_NAME = liblynx-nginx

NGINX=1.10.1

PWD = $(shell pwd)

# work out best Dockerfile to use for buidling
ifeq ($(NGINX),1.10.1)
	BASE=centos6
else
	BASE=centos7
endif

#-----------------------------------------------------------------------------
# make help displays a list of targets
#-----------------------------------------------------------------------------
.PHONY: help
help               : ## Show this help.
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

.PHONY: all
all                : ## Build all targets
all:
	@$(MAKE) module
	@$(MAKE) test-runner
	@$(MAKE) stop-nginx
	@$(MAKE) start-nginx
	@$(MAKE) test

.PHONY: module
module        : ## Build nginx module - use make module NGINX="1.10.1" to target specific version BASE="centos7" can be included to specify base Dockerfile
module:
	@echo "${BLUE}  Building for NGINX $(NGINX)...${NC}"
	@docker image build -f Dockerfile-module-$(BASE) --build-arg NGINX_VERSION=$(NGINX) -t $(DOCKER_ORG_NAME)/$(DOCKER_IMAGE_NAME):$(NGINX) . ; \
	if [ $$? -ne 0 ] ; \
		then echo "${RED}  Build failed :(${NC}" ; \
	else \
		echo "${GREEN}✓ Successfully built NGINX $(NGINX) module ${NC}" ; \
		docker run -v ${PWD}/build:/build --rm $(DOCKER_ORG_NAME)/$(DOCKER_IMAGE_NAME):$(NGINX) /bin/bash -c "cp /root/build/* /build/" ; \
	fi

.PHONY: stop-nginx
stop-nginx         : ## Stop docker container running nginx
stop-nginx:
	@docker stop "$(DOCKER_IMAGE_NAME)" ||:

.PHONY: start-nginx
start-nginx        : ## Start docker container running nginx with module
start-nginx:
	docker run --rm --name "$(DOCKER_IMAGE_NAME)" -d -p 8000:8000 $(DOCKER_ORG_NAME)/$(DOCKER_IMAGE_NAME):$(NGINX)

.PHONY: test-runner
test-runner  : ## Build container for running tests
test-runner:
	docker image build --no-cache -f Dockerfile-test -t $(DOCKER_ORG_NAME)/liblynx-nginx-test-runner .

.PHONY: test
test               : ## Run tests against nginx container
test:
	docker run --rm --link $(DOCKER_IMAGE_NAME):nginx $(DOCKER_ORG_NAME)/liblynx-nginx-test-runner

.PHONY: clean
clean              : ## Clear local copies of built binaries
clean:
	rm build/*
