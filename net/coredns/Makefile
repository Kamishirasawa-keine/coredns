include $(TOPDIR)/rules.mk

PKG_NAME:=coredns
PKG_VERSION:=1.15.0
PKG_RELEASE:=18
PKG_LICENSE:=BSD-3-Clause AND Apache-2.0 AND BSD-2-Clause AND MIT AND MPL-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_BUILD_PARALLEL:=1
PKG_BUILD_DIR=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)$(if $(COREDNS_BUILD_TAGS),-cop2)
COREDNS_SOURCE:=$(realpath $(CURDIR)/../..)
PKG_FILE_DEPENDS:=$(addprefix $(COREDNS_SOURCE)/,go.mod go.sum main.go plugin LICENSE THIRD_PARTY.md licenses scripts/collect-licenses.sh)
COREDNS_GO?=go
# Set only for an Octeon deployment with verified user-space AES/GFM support.
COREDNS_COP2_GO?=
COREDNS_BUILD_GO=$(if $(filter mips64_octeonplus,$(ARCH_PACKAGES)),$(or $(COREDNS_COP2_GO),$(COREDNS_GO)),$(COREDNS_GO))
COREDNS_COP2_FLAGS=$(if $(and $(filter mips64_octeonplus,$(ARCH_PACKAGES)),$(COREDNS_COP2_GO)),GOFIPS140=off)
COREDNS_BUILD_TAGS=$(if $(COREDNS_COP2_FLAGS),-tags=octeoncop2)

include $(INCLUDE_DIR)/package.mk

# OpenWrt uses mipsel for the architecture name; Go uses mipsle.
COREDNS_GO_ARCH:=$(if $(filter mipsel,$(ARCH)),mipsle,$(if $(filter mips64el,$(ARCH)),mips64le,$(ARCH)))

define Package/coredns
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=IP Addresses and Names
  TITLE:=CoreDNS with domain-based upstream routing$(if $(COREDNS_BUILD_TAGS), (Octeon COP2))
  URL:=https://coredns.io/
  DEPENDS:=+ca-bundle @mips||mipsel||mips64||mips64el||i386||aarch64||x86_64
endef

ifeq ($(ARCH),aarch64)
  COREDNS_GO_ARCH:=arm64
endif
ifeq ($(ARCH),i386)
  COREDNS_GO_ARCH:=386
endif
ifeq ($(ARCH),x86_64)
  COREDNS_GO_ARCH:=amd64
endif

define Package/coredns/conffiles
/etc/coredns/Corefile
/etc/coredns/local.txt
/etc/coredns/remote.txt
/etc/coredns/adblock/blocklist.txt
/etc/coredns/adblock/allowlist.txt
/etc/config/coredns
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Compile
	rm -rf $(PKG_BUILD_DIR)/plugin $(PKG_BUILD_DIR)/licenses $(PKG_BUILD_DIR)/license-bundle
	$(CP) $(COREDNS_SOURCE)/go.mod $(COREDNS_SOURCE)/go.sum $(COREDNS_SOURCE)/main.go $(COREDNS_SOURCE)/plugin $(COREDNS_SOURCE)/LICENSE $(COREDNS_SOURCE)/THIRD_PARTY.md $(COREDNS_SOURCE)/licenses $(PKG_BUILD_DIR)/
	cd $(PKG_BUILD_DIR) && \
		GOENV=off GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=$(COREDNS_GO_ARCH) \
		$(if $(filter mips mipsle,$(COREDNS_GO_ARCH)),GOMIPS=softfloat) \
		$(if $(filter mips64 mips64le,$(COREDNS_GO_ARCH)),GOMIPS64=softfloat) \
		GOFLAGS= $(COREDNS_COP2_FLAGS) "$(COREDNS_BUILD_GO)" build $(COREDNS_BUILD_TAGS) -mod=readonly -buildvcs=false -trimpath -ldflags '-s -w' -o coredns .
	cd $(PKG_BUILD_DIR) && GOENV=off GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=$(COREDNS_GO_ARCH) \
		GOFLAGS="$(COREDNS_BUILD_TAGS)" $(COREDNS_COP2_FLAGS) GO_BIN="$(COREDNS_BUILD_GO)" sh "$(COREDNS_SOURCE)/scripts/collect-licenses.sh" license-bundle
endef

define Package/coredns/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d $(1)/etc/config $(1)/etc/coredns/adblock
	$(INSTALL_DIR) $(1)/usr/share/licenses/coredns
	$(CP) $(PKG_BUILD_DIR)/license-bundle/. $(1)/usr/share/licenses/coredns/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/coredns $(1)/usr/bin/coredns
	$(INSTALL_BIN) ./files/coredns.init $(1)/etc/init.d/coredns
	$(INSTALL_CONF) ./files/coredns.config $(1)/etc/config/coredns
	$(INSTALL_CONF) ./files/Corefile $(1)/etc/coredns/Corefile
	$(INSTALL_CONF) ./files/local.txt $(1)/etc/coredns/local.txt
	$(INSTALL_CONF) ./files/remote.txt $(1)/etc/coredns/remote.txt
	$(INSTALL_CONF) ./files/empty.list $(1)/etc/coredns/adblock/blocklist.txt
	$(INSTALL_CONF) ./files/empty.list $(1)/etc/coredns/adblock/allowlist.txt
endef

$(eval $(call BuildPackage,coredns))
