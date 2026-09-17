TARGET = jailbreakd

CC = clang

CFLAGS = -Werror -Wno-availability -framework Foundation -I../.include -I./src -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path)  -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -fobjc-arc -Wno-nullability-completeness-on-arrays -O3
LDFLAGS = -L../.build -ljailbreak -lbsm

SOURCES := $(wildcard src/*.m src/*.c)
HEADERS := $(shell find src ../.include -type f -name '*.h' 2>/dev/null)
LIBRARIES := ../.build/libjailbreak.dylib

sign: $(TARGET)
	@ldid -Sentitlements.plist $<

$(TARGET): $(SOURCES) $(HEADERS) $(LIBRARIES) Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES)

clean:
	@rm -f $(TARGET)
