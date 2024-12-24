
GOCMD := go
RUSTCMD := cargo build
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
CMD_CLANG := clang


GO_SOURCE := main.go
GO_BINARY := pernis

all: build_go

build_go: $(GO_BINARY)

clean:
	$(GOCLEAN)
	rm -f $(GO_BINARY)
	rm -f user/bpf_bpfel_x86.o
	rm -f user/bpf_bpfel_x86.go

build:
	export GO111MODULE=on
	cd user/ && go generate 
	$(GOBUILD) -v -o $(GO_BINARY)  
	