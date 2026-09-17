TARGET = libkrw-dopamine.dylib
CC = clang

CFLAGS = -I../../BaseBin/.include -Isrc -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -fobjc-arc -O2
LDFLAGS = -dynamiclib -rpath @loader_path/.jbroot/usr/lib -L../../BaseBin/.build -ljailbreak

SOURCES := $(wildcard src/*.c)
HEADERS := $(shell find src ../../BaseBin/.include -type f -name '*.h' 2>/dev/null)
LIBRARIES := ../../BaseBin/.build/libjailbreak.dylib

all: $(TARGET) sign

sign: $(TARGET)
	@ldid -Cadhoc -S $^

$(TARGET): $(SOURCES) $(HEADERS) $(LIBRARIES) Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES)
	install_name_tool -change "@loader_path/libjailbreak.dylib" "@rpath/libjailbreak.dylib" $@

clean:
	@rm -f $(TARGET)
	@rm -f libkrw-dopamine.deb

package: all
	@mkdir -p .package/DEBIAN
	@mkdir -p .package/usr/lib/libkrw
	@cp control .package/DEBIAN/control
	@cp libkrw-dopamine.dylib .package/usr/lib/libkrw/libkrw-dopamine.dylib
	@dpkg-deb --root-owner-group -Zzstd -b .package ./libkrw-dopamine.deb
	@rm -rf .package
