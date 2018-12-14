#
# Copyright (C) 2018 - ntop.org
#

include $(TOPDIR)/rules.mk

PKG_NAME:=libndpi
PKG_VERSION:=1333.ab2f3ce
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/ntop/nDPI.git
PKG_SOURCE_VERSION:=ab2f3cefc89017d73e67faa4eb4011e7e3f2044d
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git

PKG_MAINTAINER:=Emanuele Faranda <faranda@ntop.org>
PKG_LICENSE:=GPL3
PKG_BUILD_DEPENDS:=+libpcap
PKG_BUILD_PARALLEL:=1

# autogen fix
PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk

define Package/libndpi
  SECTION:=network
  CATEGORY:=Network
  #DEPENDS:=+libc +libjson-c +libpthread 
  TITLE:=nDPI Deep Packet Inspection Library
  URL:=https://www.ntop.org
endef

define Package/libndpi/description
 Open and Extensible GPLv3 Deep Packet Inspection Library
endef

CONFIGURE_ARGS += \
        --with-pic \
	--disable-json-c \

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
