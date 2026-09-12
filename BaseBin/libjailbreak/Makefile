TARGET = libjailbreak.dylib
.DEFAULT_GOAL := sign

CC = clang
ARCHS = arm64 arm64e
SDKROOT := $(shell xcrun --sdk iphoneos --show-sdk-path)
BREW_PREFIX := $(shell brew --prefix)
BUILD_STANDALONE ?= 0

CPPFLAGS = -I../.include -I../_external/modules/litehook/src -I$(BREW_PREFIX)/opt/libarchive/include -F../_external/frameworks -DBUILD_STANDALONE=$(BUILD_STANDALONE)
CFLAGS = -isysroot $(SDKROOT) -miphoneos-version-min=15.0 -fobjc-arc
LDFLAGS = -framework Foundation -framework CoreServices -framework Security -framework IOKit -framework IOSurface -framework IOMobileFramebuffer -framework CoreGraphics -framework ImageIO -lMobileGestalt -larchive -lbsm -L../.build -F../_external/frameworks -lchoma -lc++

SOURCES := $(wildcard src/*.c src/*.m src/*.S src/roothider/*.c src/roothider/*.m src/roothider/*.cpp)

define architecture_rules
OBJECTS_$(1) := $(addprefix .obj/$(1)/,$(addsuffix .o,$(SOURCES))) .obj/$(1)/litehook.o

.obj/$(1)/%.o: % Makefile .obj/build-flags
	@mkdir -p $$(@D)
	$$(CC) $$(CPPFLAGS) $$(CFLAGS) -arch $(1) -MMD -MP -c $$< -o $$@

.obj/$(1)/litehook.o: ../_external/modules/litehook/src/litehook.c Makefile .obj/build-flags
	@mkdir -p $$(@D)
	$$(CC) $$(CPPFLAGS) $$(CFLAGS) -arch $(1) -MMD -MP -c $$< -o $$@

.obj/$(1)/$$(TARGET): $$(OBJECTS_$(1)) Makefile .obj/build-flags
	$$(CC) $$(CFLAGS) -arch $(1) -dynamiclib -install_name @loader_path/$$(TARGET) $$(LDFLAGS) -o $$@ $$(OBJECTS_$(1))

objects: $$(OBJECTS_$(1))
-include $$(OBJECTS_$(1):.o=.d)
endef

$(foreach architecture,$(ARCHS),$(eval $(call architecture_rules,$(architecture))))

.obj/build-flags: FORCE
	@mkdir -p $(@D)
	@printf '%s\n' '$(CC)' '$(CPPFLAGS)' '$(CFLAGS)' '$(LDFLAGS)' > $@.tmp
	@cmp -s $@.tmp $@ || mv $@.tmp $@
	@rm -f $@.tmp

sign: $(TARGET)
	@ldid -Cadhoc -S $<

$(TARGET): $(foreach architecture,$(ARCHS),.obj/$(architecture)/$(TARGET))
	xcrun lipo -create $^ -output $@

clean:
	@rm -f $(TARGET)
	@rm -rf .obj

.PHONY: clean sign objects FORCE
