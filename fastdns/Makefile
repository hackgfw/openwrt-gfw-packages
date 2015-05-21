#
# Copyright (C) 2015 hackgfw
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=fastdns
PKG_VERSION:=0.1.0

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/hackgfw/fastdns/releases/download/v$(PKG_VERSION)/
PKG_MD5SUM:=6816c3c3745aaa15314d72317485a615
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/fastdns
  SECTION:=net
  CATEGORY:=Network
  DEPENDS += +libstdcpp +librt 
  TITLE:=Fast Recursive DNS Server
  URL:=https://github.com/hackgfw/fastdns/
  MAINTAINER:=hackgfw <hackgfw@outlook.com>
endef

define Package/fastdns/description
  Fast Recursive DNS Server
  For more information, please refer to https://github.com/hackgfw/fastdns
endef

CONFIGURE_VARS += \
	CXXFLAGS="$$$$CXXFLAGS -DNDEBUG -fno-exceptions -fno-builtin -fno-rtti" \

define Build/Configure
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status}; \
		./autogen.sh \
	);
	$(call Build/Configure/Default)
endef


define Package/fastdns/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/$(PKG_NAME).init $(1)/etc/init.d/$(PKG_NAME)
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/$(PKG_NAME) $(1)/usr/sbin/$(PKG_NAME)
endef

$(eval $(call BuildPackage,fastdns))
