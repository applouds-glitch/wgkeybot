# SPDX-License-Identifier: Apache-2.0
#
# Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.

BUILDDIR ?= $(CURDIR)/build
DESTDIR ?= $(CURDIR)/out

NDK_GO_ARCH_MAP_x86 := 386
NDK_GO_ARCH_MAP_x86_64 := amd64
NDK_GO_ARCH_MAP_arm := arm
NDK_GO_ARCH_MAP_arm64 := arm64
NDK_GO_ARCH_MAP_mips := mipsx
NDK_GO_ARCH_MAP_mips64 := mips64x

comma := ,
CLANG_FLAGS := --target=$(TARGET) --sysroot=$(SYSROOT)
export CGO_CFLAGS := $(CLANG_FLAGS) $(subst -mthumb,-marm,$(CFLAGS))
export CGO_LDFLAGS := $(CLANG_FLAGS) $(patsubst -Wl$(comma)--build-id=%,-Wl$(comma)--build-id=none,$(LDFLAGS)) -Wl,-soname=libwg-go.so
export GOARCH := $(NDK_GO_ARCH_MAP_$(ANDROID_ARCH_NAME))
export GOOS := android
export CGO_ENABLED := 1

GO_BUILD_TAGS := linux
ifeq ($(CMAKE_BUILD_TYPE),Debug)
GO_BUILD_TAGS += wgdebug
endif

default: $(DESTDIR)/libwg-go.so

# Rebuild whenever anything that ends up inside the .so changes. Previously the
# target depended on go.mod alone, so edits to vk.go / turn-client.go / etc. did
# NOT trigger a rebuild on incremental Gradle builds — the stale .so was silently
# reused. Go's own build cache keeps this cheap (it only recompiles changed
# packages).
#
# The C sources belong here for the same reason, and their omission was worse:
# jni.c is compiled by this same `go build` (it is a cgo source), so a jni.c-only
# edit changed no prerequisite at all and make skipped `go build` outright. A
# newly added JNI entry point then never reached the .so, and the first call to
# it was an UnsatisfiedLinkError on a device running a freshly built APK.
#
# certs/ is in the list because vk_certs.go //go:embed's it: a rotated root CA is
# as much a source change as any .go file, and it would have been just as silent.
# The patterns go two levels deep because the tree is nested (srtpwrap/ is a
# package of its own, hostshim/android/ holds the host-build headers).
#
# out/ and build/ are filtered back out: they are the default DESTDIR/BUILDDIR,
# and `-buildmode c-shared` writes a generated libwg-go.h next to the .so, so
# matching it would make the target depend on its own output and rebuild forever.
# Spelled with $(wildcard)/$(filter-out) rather than `find` so the rule does not
# depend on a shell — NDK builds run this Makefile on Windows too.
GO_SOURCES := $(filter-out out/% build/%, $(wildcard \
	*.go */*.go */*/*.go \
	*.c *.h */*.c */*.h */*/*.c */*/*.h \
	certs/*)) \
	go.mod $(wildcard go.sum) Makefile ../CMakeLists.txt

$(DESTDIR)/libwg-go.so: $(GO_SOURCES)
	go build -tags "$(GO_BUILD_TAGS)" -ldflags="-checklinkname=0 -X golang.zx2c4.com/wireguard/ipc.socketDirectory=/data/data/$(ANDROID_PACKAGE_NAME)/cache/wireguard -buildid=" -v -trimpath -buildvcs=false -o "$@" -buildmode c-shared

.DELETE_ON_ERROR:
