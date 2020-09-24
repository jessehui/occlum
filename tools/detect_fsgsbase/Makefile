CUR_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
PROJECT_DIR := $(realpath $(CUR_DIR)/../../)

C_SRC = detect_fsgsbase.c
#C_OBJ = detect_fsgsbase
TARGET := $(PROJECT_DIR)/build/bin/detect_fsgsbase

.phony: all clean

all: $(TARGET)

$(TARGET): $(C_SRC)
	@gcc -O2 -o $@ $^
	@echo "GEN  =>  $@"

clean:
	@rm -rf $(TARGET)
