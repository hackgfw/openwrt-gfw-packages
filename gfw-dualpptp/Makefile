#
# Copyright (C) 2013 hackgfw
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=gfw-dualpptp
PKG_VERSION:=0.1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/gfw-dualpptp
  SECTION:=net
  CATEGORY:=Network
  DEPENDS += +ip +iptables-mod-tee +iptables-mod-u32
  TITLE:=VPN script to use redundant connecions
  URL:=https://github.com/hackgfw/openwrt-gfw/
  MAINTAINER:=hackgfw <hackgfw@aim.com>
endef

define Package/gfw-dualpptp/description
  VPN script to use redundant connecions, like RAID1 for VPN.
  Only pptp is supported, also need to patch kernel manually for OpenWRT 12.09 or later.
  For more information, please refer to https://github.com/hackgfw/openwrt-gfw
endef

define Package/gfw-dualpptp/conffiles
/etc/config/gfw-dualpptp
endef

define Build/Compile
endef

define Package/gfw-dualpptp/install
	$(INSTALL_DIR) $(1)/etc/ppp
	$(INSTALL_DIR) $(1)/etc/ppp/ip-up.d
	$(INSTALL_DIR) $(1)/etc/ppp/ip-down.d
	$(INSTALL_BIN) ./files/ip-up-cdual $(1)/etc/ppp/ip-up.d/ip-up-cdual
	$(INSTALL_BIN) ./files/ip-down-cdual $(1)/etc/ppp/ip-down.d/ip-down-cdual
	$(INSTALL_BIN) ./files/ip-up-client $(1)/etc/ppp/ip-up.d/ip-up-client
	$(INSTALL_BIN) ./files/ip-down-client $(1)/etc/ppp/ip-down.d/ip-down-client
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/$(PKG_NAME).config $(1)/etc/config/$(PKG_NAME)
endef

$(eval $(call BuildPackage,gfw-dualpptp))
