ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = autogen.sh

AM_CFLAGS = \
	-I $(srcdir)/include \
	-I /usr/include/dbus-1.0 \
	-I /usr/include/dbus-1.0/include \
	-I /usr/include/glib-2.0 \
	-I /usr/include/glib-2.0/include \
	-I /usr/lib64/glib-2.0 \
	-I /usr/lib64/glib-2.0/include \
	-I /home/agnieszka/Pidgin/pidgin-2.10.7/libpurple


# Helper library
#pkginclude_HEADERS = \
#        include/my-lib-test.h

#lib_LTLIBRARIES = \
#        my-lib-test.la

#my_lib_test_la_SOURCES = \
#        include/my-lib-test.h \
#        include/my-lib-test.c

#my_lib_test_la_LDFLAGS = \
#        -no-undefined \
#        -avoid-version -module \
#        -export-dynamic


# Plugin
lib_LTLIBRARIES = hka-plugin.la # +=  ??

hka_plugin_la_SOURCES = \
	src/hka-plugin.c \
	include/config.h \
	include/my-lib-test.h

hka_plugin_la_LDFLAGS = \
	-no-undefined \
	-avoid-version -module \
	-export-symbols-regex 'purple_init_(hka_plugin_)?plugin'

hka_plugin_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(PURPLE_CFLAGS) \
	$(GLIB_CFLAGS)

hka_plugin_la_LIBADD = \
	$(PURPLE_LIBS) \
	$(GLIB_LIBS)
#	my-lib-test.la

