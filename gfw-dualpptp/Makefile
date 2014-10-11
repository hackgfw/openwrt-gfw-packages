#
# Copyright (C) 2013-2014 hackgfw
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=gfw-dualpptp
PKG_VERSION:=0.2
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/gfw-dualpptp
  SECTION:=net
  CATEGORY:=Network
  DEPENDS += +ip +iptables-mod-tee +iptables-mod-u32
  PKGARCH:=all
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
	$(INSTALL_BIN) ./files/ip-up-dual $(1)/etc/ppp/ip-up.d/ip-up-dual
	$(INSTALL_BIN) ./files/ip-down-dual $(1)/etc/ppp/ip-down.d/ip-down-dual
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/$(PKG_NAME).config $(1)/etc/config/$(PKG_NAME)
endef

define Package/gfw-dualpptp/postinst
#!/bin/sh
chkfirewall=$$(grep ". /var/gfw-dualpptp.user" $${IPKG_INSTROOT}/etc/firewall.user 2>/dev/null)
if [ -z "$$chkfirewall" ]; then
	echo "[[ -s /var/gfw-dualpptp.user ]] && . /var/gfw-dualpptp.user" >> $${IPKG_INSTROOT}/etc/firewall.user
fi
exit 0
endef

define Package/gfw-dualpptp/postrm
#!/bin/sh
sed -i '/gfw-dualpptp.user/d' $${IPKG_INSTROOT}/etc/firewall.user 2>/dev/null
exit 0
endef

$(eval $(call BuildPackage,gfw-dualpptp))
