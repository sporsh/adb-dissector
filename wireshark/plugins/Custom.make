#
# $Id$
#

_CUSTOM_SUBDIRS_ = \
	adb

_CUSTOM_EXTRA_DIST_ = \
	Custom.m4 \
	Custom.make

_CUSTOM_plugin_ldadd_ = \
	-dlopen plugins/adb/adb.la
