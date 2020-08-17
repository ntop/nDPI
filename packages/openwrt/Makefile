#
# Copyright (C) 2018-20 - ntop.org
#

include $(TOPDIR)/rules.mk

PKG_NAME:=libndpi
PKG_VERSION:=17022020
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/ntop/nDPI.git
PKG_SOURCE_VERSION:=1f921562d1d7962f1d23ca5b59c25f9b65073460
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git

PKG_MAINTAINER:=Luca Deri <deri@ntop.org>
PKG_LICENSE:=GPL3
PKG_BUILD_DEPENDS:=
PKG_BUILD_PARALLEL:=1

# autogen fix
PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk

define Package/libndpi
  SECTION:=network
  CATEGORY:=Network
  TITLE:=nDPI Deep Packet Inspection Library
  URL:=https://www.ntop.org
endef

define Package/libndpi/description
 Open and Extensible GPLv3 Deep Packet Inspection Library
endef

CONFIGURE_ARGS += \
	--with-only-libndpi

define Build/Prepare
	$(call Build/Prepare/Default)
endef

define Build/Configure
	( cd $(PKG_BUILD_DIR); ./autogen.sh )
	$(call Build/Configure/Default)
endef

define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR)/usr/local/include/libndpi
	$(CP) $(PKG_BUILD_DIR)/src/include/* $(STAGING_DIR)/usr/local/include/libndpi
	$(INSTALL_DIR) $(STAGING_DIR)/usr/local/lib
	$(CP) $(PKG_BUILD_DIR)/src/lib/libndpi.* $(STAGING_DIR)/usr/local/lib
endef

$(eval $(call BuildPackage,libndpi))
