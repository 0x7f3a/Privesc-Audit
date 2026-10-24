# privesc-auditor — build configuration
#
#   make            Linux/macOS build (warnings + hardening)
#   make san        sanitizer build used while developing
#   make win        cross-compile the Windows binary (needs mingw-w64)
#   make test       build every variant and run tests/run.sh
#   make clean      remove build outputs

CC     ?= cc
WCC    ?= x86_64-w64-mingw32-gcc
SRC    := main.c
BIN    := privesc-auditor
EXE    := privesc-auditor.exe
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong
SANFLAGS := -std=c11 -Wall -Wextra -Wpedantic -g -O1 \
            -fsanitize=address,undefined -fno-omit-frame-pointer

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

san:
	$(CC) $(SANFLAGS) -o privesc-auditor.san $(SRC)

win:
	$(WCC) $(CFLAGS) -o $(EXE) $(SRC)

test:
	tests/run.sh

clean:
	rm -f $(BIN) $(EXE) privesc-auditor.san

.PHONY: all san win test clean