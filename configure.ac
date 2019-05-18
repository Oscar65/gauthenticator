AC_PREREQ(2.61)
AC_INIT(gauthenticator, 0.01, megia_oscar@gmail.com)
AC_CONFIG_SRCDIR([src/gauthenticator.c])
AC_CONFIG_AUX_DIR([build])
AC_CONFIG_MACRO_DIR([build])

# --enable-silent-rules
m4_ifdef([AM_SILENT_RULES],
  [AM_SILENT_RULES([yes])],
  [AC_SUBST([AM_DEFAULT_VERBOSITY], [1])])

AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AM_MAINTAINER_MODE([enable])

LT_INIT
AC_PROG_CC
AC_PROG_CC_STDC

 # Checks for libraries
AM_PATH_GTK_3_0(3.24.8,,AC_MSG_ERROR(gauthenticator was developed with GTK+ 3.24.8. Try to change this line and new functions for functions available in your GTK+ version))

PKG_CHECK_MODULES(LIBSECRET, [libsecret-1 >= 0.18.7])
AC_SUBST(LIBSECRET_CFLAGS)
AC_SUBST(LIBSECRET_LIBS)

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo "
  $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  Debug Build....: $debug
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
"

AC_MSG_NOTICE([
------------------------------------------------------------------------------
Now type 'make ; sudo make install' to build and install $PACKAGE-$VERSION
See file README.md for more information.
You can uninstall $PACKAGE-$VERSION by typing 'sudo make uninstall'
------------------------------------------------------------------------------
])
