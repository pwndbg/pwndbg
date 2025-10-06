# Copyright (C) 2020-2025 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# A makefile snippet that lists all of the libraries that should be
# pulled in when linking against gnulib.  Both GDB and GDBSERVER will
# include this snippet.
#
# The defined variables are:
#
# LIBGNU: The path to the archive containing gnulib.  Can be used as a
#        dependency as when this file changes gdb/gdbserver should be
#        relinked.
#
# LIBGNU_EXTRA_LIBS: A list of linker -l.... flags that should be
#        included in the link line of gdb/gdbserver.  These are
#        libraries that $(LIBGNU) depends on.  This list is taken from
#        the output of gnulib-tool, which is run by our
#        gnulib/update-gnulib.sh script.
#
# INCGNU: A list of -I.... include paths that should be passed to the
#        compiler, these are where the gnulib headers can be found.

# Packages must define the relative path to gnulib's parent dir.
ifndef GNULIB_PARENT_DIR
$(error missing GNULIB_PARENT_DIR)
endif

LIBGNU = $(GNULIB_PARENT_DIR)/gnulib/import/libgnu.a
LIBGNU_EXTRA_LIBS =    \
                       \
                      \
                       
INCGNU = -I$(srcdir)/$(GNULIB_PARENT_DIR)/gnulib/import \
         -I$(GNULIB_PARENT_DIR)/gnulib/import
