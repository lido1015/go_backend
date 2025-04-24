# COLORS
GREEN        := $(shell tput -Txterm setaf 2)
YELLOW       := $(shell tput -Txterm setaf 3)
RESET := $(shell tput -Txterm sgr0)


run:
	go run src/main.go -develop -http

format:
	gofumpt -l -w .

doc:
	@echo "${YELLOW}Generate Swagger docs${RESET}"
	swag init --dir src --output src/docs

build-production: doc
	@echo "${YELLOW}Building${RESET}"
	go env -w GOOS=linux
	go env -w GOARCH=amd64
	go build -ldflags="-s -w" -o gestion_linux_amd64.bin src/main.go
	go env -w GOOS=darwin
	go env -w GOARCH=arm64
	@echo "${YELLOW}Compressing${RESET}"
	upx --brute gestion_linux_amd64.bin

