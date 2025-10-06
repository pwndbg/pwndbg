/* DO NOT EDIT! GENERATED AUTOMATICALLY! */
/* Substitute for <sys/uio.h>.
   Copyright (C) 2011-2022 Free Software Foundation, Inc.

   This file is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of the
   License, or (at your option) any later version.

   This file is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

# if __GNUC__ >= 3
#pragma GCC system_header
# endif


#ifndef _GL_SYS_UIO_H

#if 1

/* On OpenBSD 4.4, <sys/uio.h> assumes prior inclusion of <sys/types.h>.  */
# include <sys/types.h>

/* The include_next requires a split double-inclusion guard.  */
# include_next <sys/uio.h>

#endif

#ifndef _GL_SYS_UIO_H
#define _GL_SYS_UIO_H

#if !1
/* A platform that lacks <sys/uio.h>.  */
/* Get 'size_t' and 'ssize_t'.  */
# include <sys/types.h>

# ifdef __cplusplus
extern "C" {
# endif

# if !GNULIB_defined_struct_iovec
/* All known platforms that lack <sys/uio.h> also lack any declaration
   of struct iovec in any other header.  */
struct iovec {
  void *iov_base;
  size_t iov_len;
};
#  define GNULIB_defined_struct_iovec 1
# endif

# ifdef __cplusplus
}
# endif

#endif

#endif /* _GL_SYS_UIO_H */
#endif /* _GL_SYS_UIO_H */
