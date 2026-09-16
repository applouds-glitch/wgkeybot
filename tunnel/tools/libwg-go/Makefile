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

# Rebuild whenever any Go source (this module's *.go plus go.mod/go.sum)
# changes. Previously the target depended on go.mod alone, so edits to
# vk.go / turn-client.go / etc. did NOT trigger a rebuild on incremental
# Gradle builds — the stale .so was silently reused. Go's own build cache
# keeps this cheap (it only recompiles changed packages).
GO_SOURCES := $(wildcard *.go) go.mod $(wildcard go.sum) Makefile ../CMakeLists.txt

$(DESTDIR)/libwg-go.so: $(GO_SOURCES)
	go build -tags "$(GO_BUILD_TAGS)" -ldflags="-checklinkname=0 -X golang.zx2c4.com/wireguard/ipc.socketDirectory=/data/data/$(ANDROID_PACKAGE_NAME)/cache/wireguard -buildid=" -v -trimpath -buildvcs=false -o "$@" -buildmode c-shared

.DELETE_ON_ERROR:
