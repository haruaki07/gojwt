all: build run

build:
	@go build -o tmp/main.exe

run:
	@./tmp/main.exe

.PHONY: build run