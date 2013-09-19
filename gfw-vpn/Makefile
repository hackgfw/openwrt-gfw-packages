#
# Copyright (C) 2013 hackgfw
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=gfw-vpn
PKG_VERSION:=0.1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/gfw-vpn
  SECTION:=net
  CATEGORY:=Network
  DEPENDS += +ip +ipset +iptables-mod-ipopt
  TITLE:=VPN script to tear down gfw
  URL:=https://github.com/hackgfw/openwrt-gfw/
  MAINTAINER:=hackgfw <hackgfw@aim.com>
endef

define Package/gfw-vpn/description
  VPN script to tear down gfw
  For more information, please refer to https://github.com/hackgfw/openwrt-gfw
endef

define Package/gfw-vpn/conffiles
/etc/config/gfw-vpn
endef

define Build/Compile
endef

define Package/gfw-vpn/install
	$(INSTALL_DIR) $(1)/etc/ppp
	$(INSTALL_DIR) $(1)/etc/ppp/ip-up.d
	$(INSTALL_DIR) $(1)/etc/ppp/ip-down.d
	$(INSTALL_BIN) ./files/ip-up-wall $(1)/etc/ppp/ip-up.d/ip-up-wall
	$(INSTALL_BIN) ./files/ip-down-wall $(1)/etc/ppp/ip-down.d/ip-down-wall
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/$(PKG_NAME).config $(1)/etc/config/$(PKG_NAME)
	$(INSTALL_CONF) ./files/$(PKG_NAME).whiteip $(1)/etc/config/$(PKG_NAME).whiteip
	$(INSTALL_CONF) ./files/$(PKG_NAME).whitezone $(1)/etc/config/$(PKG_NAME).whitezone
endef

$(eval $(call BuildPackage,gfw-vpn))
