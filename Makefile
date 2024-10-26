PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ELF := byepervisor.elf

CFLAGS := -std=c++11 -Wall -Werror -g -I./include -DHEN_BIN_PATH="\"hen/hen.bin\"" -lSceSystemService

all: $(ELF)

$(ELF): src/main.cpp src/kdlsym.cpp src/kexec.cpp src/mirror.cpp src/paging.cpp src/patching.cpp src/self.cpp src/util.cpp src/hen.S
	$(CXX) $(CFLAGS) -o $@ $^

clean:
	rm -f $(ELF)

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

debug: $(ELF)
	gdb \
	-ex "target extended-remote $(PS5_HOST):2159" \
	-ex "file $(ELF)" \
	-ex "remote put $(ELF) /data/$(ELF)" \
	-ex "set remote exec-file /data/$(ELF)" \
	-ex "start"
