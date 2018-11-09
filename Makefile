export DEVELOPER_DIR := $(shell xcode-select --print-path)
SDK_OSX := $(shell xcodebuild -version -sdk macosx Path)

CC_OSX = xcrun -sdk "macosx" clang
LD_OSX = $(CC_OSX)

MIN_VER_OSX = "-mmacosx-version-min=10.10"
ARCH_OSX = -arch x86_64
CFLAGS = -g -I$(SDK_OSX)/usr/include -I./imobiledevice-v2.0/include -I.
LDFLAGS = -L./imobiledevice-v2.0/lib -limobiledevice -lplist -lcrypto -lssl -lusbmuxd -lxml2 -lz -llzma -liconv

TOOL_NAME = ios-8.1.2-jb-userland

all: $(TOOL_NAME).c
	$(CC_OSX) -o $(TOOL_NAME) $(TOOL_NAME).c utils.c -lpthread $(CFLAGS) $(LDFLAGS) $(ARCH_OSX) $(MIN_VER_OSX) -isysroot $(SDK_OSX) 

clean:
	rm -rf $(TOOL_NAME) $(TOOL_NAME).dSYM
