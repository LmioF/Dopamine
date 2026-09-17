TARGET = launchdhook.dylib
CC = clang

CFLAGS = -framework Foundation -framework CoreServices -framework Security -I../.include -Isrc -I../_external/modules/litehook/src -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -Wno-deprecated-declarations -D BUILD_STANDALONE=$(BUILD_STANDALONE) -fobjc-arc -O2
LDFLAGS = -dynamiclib -rpath @loader_path/present -rpath @loader_path/fallback -L../.build -L../_external/lib -ljailbreak -lbsm -lchoma -lMobileGestalt

SOURCES := $(wildcard src/*.m src/*.c src/jbserver/*.c ../systemhook/src/common/*.[cSm] ../systemhook/src/envbuf.c ../systemhook/src/roothider_common.c ../_external/modules/litehook/src/*.c)
HEADERS := $(shell find src ../.include ../systemhook/src ../_external/modules/litehook/src -type f -name '*.h' 2>/dev/null)
LIBRARIES := ../.build/libjailbreak.dylib ../.build/libchoma.dylib $(wildcard ../_external/lib/libMobileGestalt.*)

sign: $(TARGET)
	@ldid -Cadhoc -S $^

$(TARGET): $(SOURCES) $(HEADERS) $(LIBRARIES) Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES)

clean:
	@rm -f $(TARGET)
