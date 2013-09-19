#
# Copyright (C) 2013 hackgfw
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=gfw-dns
PKG_VERSION:=0.1.1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DEPENDS += +dnsmasq +firewall

include $(INCLUDE_DIR)/package.mk

define Package/gfw-dns
  SECTION:=net
  CATEGORY:=Network
  DEPENDS += +bind-dig +iptables-mod-filter +iptables-mod-u32 +dnsmasq +firewall
  TITLE:=AntiDNSPoisoning
  URL:=https://github.com/hackgfw/openwrt-gfw/
  MAINTAINER:=hackgfw <hackgfw@aim.com>
endef

define Package/gfw-dns/description
  AntiDNSPoisoning
  For more information, please refer to https://github.com/hackgfw/openwrt-gfw
endef

define Package/gfw-dns/conffiles
/etc/config/gfw-dns
endef

define Build/Compile
endef

define Package/gfw-dns/install
	$(INSTALL_DIR) $(1)/etc/crontabs
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/$(PKG_NAME).init $(1)/etc/init.d/$(PKG_NAME)
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/$(PKG_NAME).config $(1)/etc/config/$(PKG_NAME)
	$(INSTALL_DIR) $(1)/usr/lib/$(PKG_NAME)
	$(INSTALL_BIN) ./files/$(PKG_NAME).sh $(1)/usr/lib/$(PKG_NAME)/$(PKG_NAME).sh
endef

define Package/gfw-dns/postinst
#!/bin/sh
chkdnsmasq=$$(grep ^all-servers $${IPKG_INSTROOT}/etc/dnsmasq.conf 2>/dev/null)
if [ -z "$$chkdnsmasq" ]; then
	echo "all-servers" >> $${IPKG_INSTROOT}/etc/dnsmasq.conf
fi
chkcrontabs=$$(grep "/etc/init.d/gfw-dns start" $${IPKG_INSTROOT}/etc/crontabs/root 2>/dev/null)
if [ -z "$$chkcrontabs" ]; then
	echo "0 6 * * * /etc/init.d/gfw-dns start" >> $${IPKG_INSTROOT}/etc/crontabs/root
fi
chkfirewall=$$(grep ". /var/g.firewall.user" $${IPKG_INSTROOT}/etc/firewall.user 2>/dev/null)
if [ -z "$$chkfirewall" ]; then
	echo ". /var/g.firewall.user" >> $${IPKG_INSTROOT}/etc/firewall.user
fi
endef

define Package/gfw-dns/postrm
#!/bin/sh
sed -i '/gfw-dns/d' $${IPKG_INSTROOT}/etc/crontabs/root 2>/dev/null
sed -i '/g.firewall.user/d' $${IPKG_INSTROOT}/etc/firewall.user 2>/dev/null
exit 0
endef

$(eval $(call BuildPackage,gfw-dns))
