include $(TOPDIR)/rules.mk

PKG_VERSION:=1.0.0
PKG_RELEASE:=18
PKG_LICENSE:=BSD-3-Clause
SIMPLIFIEDNS_SOURCE:=$(realpath $(CURDIR)/../..)
PKG_FILE_DEPENDS:=$(SIMPLIFIEDNS_SOURCE)/LICENSE

define Build/Prepare/luci-app-coredns
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/root/usr/share/licenses/luci-app-coredns
	$(INSTALL_DATA) $(SIMPLIFIEDNS_SOURCE)/LICENSE $(PKG_BUILD_DIR)/root/usr/share/licenses/luci-app-coredns/LICENSE
endef

LUCI_TITLE:=LuCI support for CoreDNS
LUCI_DEPENDS:=+luci-base +coredns +rpcd-mod-ucode +ucode-mod-fs +uclient-fetch +coreutils-timeout +flock

define Package/luci-app-coredns/conffiles
/etc/config/coredns-subscriptions
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - required for discovery in an external feed.
