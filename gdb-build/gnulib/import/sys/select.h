/* DO NOT EDIT! GENERATED AUTOMATICALLY! */
/* Substitute for <sys/select.h>.
   Copyright (C) 2007-2022 Free Software Foundation, Inc.

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


/* On OSF/1 and Solaris 2.6, <sys/types.h> and <sys/time.h>
   both include <sys/select.h>.
   On Cygwin and OpenBSD, <sys/time.h> includes <sys/select.h>.
   Simply delegate to the system's header in this case.  */
#if (1                                                \
     && !defined _GL_SYS_SELECT_H_REDIRECT_FROM_SYS_TYPES_H             \
     && ((defined __osf__ && defined _SYS_TYPES_H_                      \
          && defined _OSF_SOURCE)                                       \
         || (defined __sun && defined _SYS_TYPES_H                      \
             && (! (defined _XOPEN_SOURCE || defined _POSIX_C_SOURCE)   \
                 || defined __EXTENSIONS__))))

# define _GL_SYS_SELECT_H_REDIRECT_FROM_SYS_TYPES_H
# include_next <sys/select.h>

#elif (1                                              \
       && (defined _CYGWIN_SYS_TIME_H                                   \
           || (!defined _GL_SYS_SELECT_H_REDIRECT_FROM_SYS_TIME_H       \
               && ((defined __osf__ && defined _SYS_TIME_H_             \
                    && defined _OSF_SOURCE)                             \
                   || (defined __OpenBSD__ && defined _SYS_TIME_H_)     \
                   || (defined __sun && defined _SYS_TIME_H             \
                       && (! (defined _XOPEN_SOURCE                     \
                              || defined _POSIX_C_SOURCE)               \
                           || defined __EXTENSIONS__))))))

# define _GL_SYS_SELECT_H_REDIRECT_FROM_SYS_TIME_H
# include_next <sys/select.h>

/* On IRIX 6.5, <sys/timespec.h> includes <sys/types.h>, which includes
   <sys/bsd_types.h>, which includes <sys/select.h>.  At this point we cannot
   include <signal.h>, because that includes <internal/signal_core.h>, which
   gives a syntax error because <sys/timespec.h> has not been completely
   processed.  Simply delegate to the system's header in this case.  */
#elif 1 && defined __sgi && (defined _SYS_BSD_TYPES_H && !defined _GL_SYS_SELECT_H_REDIRECT_FROM_SYS_BSD_TYPES_H)

# define _GL_SYS_SELECT_H_REDIRECT_FROM_SYS_BSD_TYPES_H
# include_next <sys/select.h>

/* On OpenBSD 5.0, <pthread.h> includes <sys/types.h>, which includes
   <sys/select.h>.  At this point we cannot include <signal.h>, because that
   includes gnulib's pthread.h override, which gives a syntax error because
   /usr/include/pthread.h has not been completely processed.  Simply delegate
   to the system's header in this case.  */
#elif 1 && defined __OpenBSD__ && (defined _PTHREAD_H_ && !defined PTHREAD_MUTEX_INITIALIZER)

# include_next <sys/select.h>

#else

#ifndef _GL_SYS_SELECT_H

/* On many platforms, <sys/select.h> assumes prior inclusion of
   <sys/types.h>.  Also, mingw defines sigset_t there, instead of
   in <signal.h> where it belongs.  */
#include <sys/types.h>

#if 1

/* On OSF/1 4.0, <sys/select.h> provides only a forward declaration
   of 'struct timeval', and no definition of this type.
   Also, Mac OS X, AIX, HP-UX, IRIX, Solaris, Interix declare select()
   in <sys/time.h>.
   But avoid namespace pollution on glibc systems and "unknown type
   name" problems on Cygwin.  */
# if !(defined __GLIBC__ || defined __CYGWIN__)
#  include <sys/time.h>
# endif

/* On AIX 7 and Solaris 10, <sys/select.h> provides an FD_ZERO implementation
   that relies on memset(), but without including <string.h>.
   But in any case avoid namespace pollution on glibc systems.  */
# if (defined __OpenBSD__ || defined _AIX || defined __sun || defined __osf__ || defined __BEOS__) \
     && ! defined __GLIBC__
#  include <string.h>
# endif

/* The include_next requires a split double-inclusion guard.  */
# include_next <sys/select.h>

#endif

/* Get definition of 'sigset_t'.
   But avoid namespace pollution on glibc systems and "unknown type
   name" problems on Cygwin.
   On OS/2 kLIBC, sigset_t is defined in <sys/select.h>, too. In addition,
   if <sys/param.h> is included, <types.h> -> <sys/types.h> -> <sys/select.h>
   are included. Then <signal.h> -> <pthread.h> are included by GNULIB. By the
   way, <pthread.h> requires PAGE_SIZE defined in <sys/param.h>. However,
   <sys/param.h> has not been processed, yet. As a result, 'PAGE_SIZE'
   undeclared error occurs in <pthread.h>.
   Do this after the include_next (for the sake of OpenBSD 5.0) but before
   the split double-inclusion guard (for the sake of Solaris).  */
#if !((defined __GLIBC__ || defined __CYGWIN__ || defined __KLIBC__) \
      && !defined __UCLIBC__)
# include <signal.h>
#endif

#ifndef _GL_SYS_SELECT_H
#define _GL_SYS_SELECT_H

#if !1
/* A platform that lacks <sys/select.h>.  */
/* Get the 'struct timeval' and 'fd_set' types and the FD_* macros
   on most platforms.  */
# include <sys/time.h>
/* On HP-UX 11, <sys/time.h> provides an FD_ZERO implementation
   that relies on memset(), but without including <string.h>.  */
# if defined __hpux
#  include <string.h>
# endif
/* On native Windows platforms:
   Get the 'fd_set' type.
   Get the close() declaration before we override it.  */
# if 0
#  if !defined _GL_INCLUDING_WINSOCK2_H
#   define _GL_INCLUDING_WINSOCK2_H
#   include <winsock2.h>
#   undef _GL_INCLUDING_WINSOCK2_H
#  endif
#  include <io.h>
# endif
#endif

/* The definitions of _GL_FUNCDECL_RPL etc. are copied here.  */
/* C++ compatible function declaration macros.
   Copyright (C) 2010-2022 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as published
   by the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

#ifndef _GL_CXXDEFS_H
#define _GL_CXXDEFS_H

/* Begin/end the GNULIB_NAMESPACE namespace.  */
#if defined __cplusplus && defined GNULIB_NAMESPACE
# define _GL_BEGIN_NAMESPACE namespace GNULIB_NAMESPACE {
# define _GL_END_NAMESPACE }
#else
# define _GL_BEGIN_NAMESPACE
# define _GL_END_NAMESPACE
#endif

/* The three most frequent use cases of these macros are:

   * For providing a substitute for a function that is missing on some
     platforms, but is declared and works fine on the platforms on which
     it exists:

       #if @GNULIB_FOO@
       # if !@HAVE_FOO@
       _GL_FUNCDECL_SYS (foo, ...);
       # endif
       _GL_CXXALIAS_SYS (foo, ...);
       _GL_CXXALIASWARN (foo);
       #elif defined GNULIB_POSIXCHECK
       ...
       #endif

   * For providing a replacement for a function that exists on all platforms,
     but is broken/insufficient and needs to be replaced on some platforms:

       #if @GNULIB_FOO@
       # if @REPLACE_FOO@
       #  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
       #   undef foo
       #   define foo rpl_foo
       #  endif
       _GL_FUNCDECL_RPL (foo, ...);
       _GL_CXXALIAS_RPL (foo, ...);
       # else
       _GL_CXXALIAS_SYS (foo, ...);
       # endif
       _GL_CXXALIASWARN (foo);
       #elif defined GNULIB_POSIXCHECK
       ...
       #endif

   * For providing a replacement for a function that exists on some platforms
     but is broken/insufficient and needs to be replaced on some of them and
     is additionally either missing or undeclared on some other platforms:

       #if @GNULIB_FOO@
       # if @REPLACE_FOO@
       #  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
       #   undef foo
       #   define foo rpl_foo
       #  endif
       _GL_FUNCDECL_RPL (foo, ...);
       _GL_CXXALIAS_RPL (foo, ...);
       # else
       #  if !@HAVE_FOO@   or   if !@HAVE_DECL_FOO@
       _GL_FUNCDECL_SYS (foo, ...);
       #  endif
       _GL_CXXALIAS_SYS (foo, ...);
       # endif
       _GL_CXXALIASWARN (foo);
       #elif defined GNULIB_POSIXCHECK
       ...
       #endif
*/

/* _GL_EXTERN_C declaration;
   performs the declaration with C linkage.  */
#if defined __cplusplus
# define _GL_EXTERN_C extern "C"
#else
# define _GL_EXTERN_C extern
#endif

/* _GL_FUNCDECL_RPL (func, rettype, parameters_and_attributes);
   declares a replacement function, named rpl_func, with the given prototype,
   consisting of return type, parameters, and attributes.
   Example:
     _GL_FUNCDECL_RPL (open, int, (const char *filename, int flags, ...)
                                  _GL_ARG_NONNULL ((1)));
 */
#define _GL_FUNCDECL_RPL(func,rettype,parameters_and_attributes) \
  _GL_FUNCDECL_RPL_1 (rpl_##func, rettype, parameters_and_attributes)
#define _GL_FUNCDECL_RPL_1(rpl_func,rettype,parameters_and_attributes) \
  _GL_EXTERN_C rettype rpl_func parameters_and_attributes

/* _GL_FUNCDECL_SYS (func, rettype, parameters_and_attributes);
   declares the system function, named func, with the given prototype,
   consisting of return type, parameters, and attributes.
   Example:
     _GL_FUNCDECL_SYS (open, int, (const char *filename, int flags, ...)
                                  _GL_ARG_NONNULL ((1)));
 */
#define _GL_FUNCDECL_SYS(func,rettype,parameters_and_attributes) \
  _GL_EXTERN_C rettype func parameters_and_attributes

/* _GL_CXXALIAS_RPL (func, rettype, parameters);
   declares a C++ alias called GNULIB_NAMESPACE::func
   that redirects to rpl_func, if GNULIB_NAMESPACE is defined.
   Example:
     _GL_CXXALIAS_RPL (open, int, (const char *filename, int flags, ...));

   Wrapping rpl_func in an object with an inline conversion operator
   avoids a reference to rpl_func unless GNULIB_NAMESPACE::func is
   actually used in the program.  */
#define _GL_CXXALIAS_RPL(func,rettype,parameters) \
  _GL_CXXALIAS_RPL_1 (func, rpl_##func, rettype, parameters)
#if defined __cplusplus && defined GNULIB_NAMESPACE
# define _GL_CXXALIAS_RPL_1(func,rpl_func,rettype,parameters) \
    namespace GNULIB_NAMESPACE                                \
    {                                                         \
      static const struct _gl_ ## func ## _wrapper            \
      {                                                       \
        typedef rettype (*type) parameters;                   \
                                                              \
        inline operator type () const                         \
        {                                                     \
          return ::rpl_func;                                  \
        }                                                     \
      } func = {};                                            \
    }                                                         \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#else
# define _GL_CXXALIAS_RPL_1(func,rpl_func,rettype,parameters) \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#endif

/* _GL_CXXALIAS_MDA (func, rettype, parameters);
   is to be used when func is a Microsoft deprecated alias, on native Windows.
   It declares a C++ alias called GNULIB_NAMESPACE::func
   that redirects to _func, if GNULIB_NAMESPACE is defined.
   Example:
     _GL_CXXALIAS_MDA (open, int, (const char *filename, int flags, ...));
 */
#define _GL_CXXALIAS_MDA(func,rettype,parameters) \
  _GL_CXXALIAS_RPL_1 (func, _##func, rettype, parameters)

/* _GL_CXXALIAS_RPL_CAST_1 (func, rpl_func, rettype, parameters);
   is like  _GL_CXXALIAS_RPL_1 (func, rpl_func, rettype, parameters);
   except that the C function rpl_func may have a slightly different
   declaration.  A cast is used to silence the "invalid conversion" error
   that would otherwise occur.  */
#if defined __cplusplus && defined GNULIB_NAMESPACE
# define _GL_CXXALIAS_RPL_CAST_1(func,rpl_func,rettype,parameters) \
    namespace GNULIB_NAMESPACE                                     \
    {                                                              \
      static const struct _gl_ ## func ## _wrapper                 \
      {                                                            \
        typedef rettype (*type) parameters;                        \
                                                                   \
        inline operator type () const                              \
        {                                                          \
          return reinterpret_cast<type>(::rpl_func);               \
        }                                                          \
      } func = {};                                                 \
    }                                                              \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#else
# define _GL_CXXALIAS_RPL_CAST_1(func,rpl_func,rettype,parameters) \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#endif

/* _GL_CXXALIAS_MDA_CAST (func, rettype, parameters);
   is like  _GL_CXXALIAS_MDA (func, rettype, parameters);
   except that the C function func may have a slightly different declaration.
   A cast is used to silence the "invalid conversion" error that would
   otherwise occur.  */
#define _GL_CXXALIAS_MDA_CAST(func,rettype,parameters) \
  _GL_CXXALIAS_RPL_CAST_1 (func, _##func, rettype, parameters)

/* _GL_CXXALIAS_SYS (func, rettype, parameters);
   declares a C++ alias called GNULIB_NAMESPACE::func
   that redirects to the system provided function func, if GNULIB_NAMESPACE
   is defined.
   Example:
     _GL_CXXALIAS_SYS (open, int, (const char *filename, int flags, ...));

   Wrapping func in an object with an inline conversion operator
   avoids a reference to func unless GNULIB_NAMESPACE::func is
   actually used in the program.  */
#if defined __cplusplus && defined GNULIB_NAMESPACE
# define _GL_CXXALIAS_SYS(func,rettype,parameters)            \
    namespace GNULIB_NAMESPACE                                \
    {                                                         \
      static const struct _gl_ ## func ## _wrapper            \
      {                                                       \
        typedef rettype (*type) parameters;                   \
                                                              \
        inline operator type () const                         \
        {                                                     \
          return ::func;                                      \
        }                                                     \
      } func = {};                                            \
    }                                                         \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#else
# define _GL_CXXALIAS_SYS(func,rettype,parameters) \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#endif

/* _GL_CXXALIAS_SYS_CAST (func, rettype, parameters);
   is like  _GL_CXXALIAS_SYS (func, rettype, parameters);
   except that the C function func may have a slightly different declaration.
   A cast is used to silence the "invalid conversion" error that would
   otherwise occur.  */
#if defined __cplusplus && defined GNULIB_NAMESPACE
# define _GL_CXXALIAS_SYS_CAST(func,rettype,parameters) \
    namespace GNULIB_NAMESPACE                          \
    {                                                   \
      static const struct _gl_ ## func ## _wrapper      \
      {                                                 \
        typedef rettype (*type) parameters;             \
                                                        \
        inline operator type () const                   \
        {                                               \
          return reinterpret_cast<type>(::func);        \
        }                                               \
      } func = {};                                      \
    }                                                   \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#else
# define _GL_CXXALIAS_SYS_CAST(func,rettype,parameters) \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#endif

/* _GL_CXXALIAS_SYS_CAST2 (func, rettype, parameters, rettype2, parameters2);
   is like  _GL_CXXALIAS_SYS (func, rettype, parameters);
   except that the C function is picked among a set of overloaded functions,
   namely the one with rettype2 and parameters2.  Two consecutive casts
   are used to silence the "cannot find a match" and "invalid conversion"
   errors that would otherwise occur.  */
#if defined __cplusplus && defined GNULIB_NAMESPACE
  /* The outer cast must be a reinterpret_cast.
     The inner cast: When the function is defined as a set of overloaded
     functions, it works as a static_cast<>, choosing the designated variant.
     When the function is defined as a single variant, it works as a
     reinterpret_cast<>. The parenthesized cast syntax works both ways.  */
# define _GL_CXXALIAS_SYS_CAST2(func,rettype,parameters,rettype2,parameters2) \
    namespace GNULIB_NAMESPACE                                                \
    {                                                                         \
      static const struct _gl_ ## func ## _wrapper                            \
      {                                                                       \
        typedef rettype (*type) parameters;                                   \
                                                                              \
        inline operator type () const                                         \
        {                                                                     \
          return reinterpret_cast<type>((rettype2 (*) parameters2)(::func));  \
        }                                                                     \
      } func = {};                                                            \
    }                                                                         \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#else
# define _GL_CXXALIAS_SYS_CAST2(func,rettype,parameters,rettype2,parameters2) \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#endif

/* _GL_CXXALIASWARN (func);
   causes a warning to be emitted when ::func is used but not when
   GNULIB_NAMESPACE::func is used.  func must be defined without overloaded
   variants.  */
#if defined __cplusplus && defined GNULIB_NAMESPACE
# define _GL_CXXALIASWARN(func) \
   _GL_CXXALIASWARN_1 (func, GNULIB_NAMESPACE)
# define _GL_CXXALIASWARN_1(func,namespace) \
   _GL_CXXALIASWARN_2 (func, namespace)
/* To work around GCC bug <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=43881>,
   we enable the warning only when not optimizing.  */
# if !(defined __GNUC__ && !defined __clang__ && __OPTIMIZE__)
#  define _GL_CXXALIASWARN_2(func,namespace) \
    _GL_WARN_ON_USE (func, \
                     "The symbol ::" #func " refers to the system function. " \
                     "Use " #namespace "::" #func " instead.")
# elif __GNUC__ >= 3 && GNULIB_STRICT_CHECKING
#  define _GL_CXXALIASWARN_2(func,namespace) \
     extern __typeof__ (func) func
# else
#  define _GL_CXXALIASWARN_2(func,namespace) \
     _GL_EXTERN_C int _gl_cxxalias_dummy
# endif
#else
# define _GL_CXXALIASWARN(func) \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#endif

/* _GL_CXXALIASWARN1 (func, rettype, parameters_and_attributes);
   causes a warning to be emitted when the given overloaded variant of ::func
   is used but not when GNULIB_NAMESPACE::func is used.  */
#if defined __cplusplus && defined GNULIB_NAMESPACE
# define _GL_CXXALIASWARN1(func,rettype,parameters_and_attributes) \
   _GL_CXXALIASWARN1_1 (func, rettype, parameters_and_attributes, \
                        GNULIB_NAMESPACE)
# define _GL_CXXALIASWARN1_1(func,rettype,parameters_and_attributes,namespace) \
   _GL_CXXALIASWARN1_2 (func, rettype, parameters_and_attributes, namespace)
/* To work around GCC bug <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=43881>,
   we enable the warning only when not optimizing.  */
# if !(defined __GNUC__ && !defined __clang__ && __OPTIMIZE__)
#  define _GL_CXXALIASWARN1_2(func,rettype,parameters_and_attributes,namespace) \
    _GL_WARN_ON_USE_CXX (func, rettype, rettype, parameters_and_attributes, \
                         "The symbol ::" #func " refers to the system function. " \
                         "Use " #namespace "::" #func " instead.")
# else
#  define _GL_CXXALIASWARN1_2(func,rettype,parameters_and_attributes,namespace) \
     _GL_EXTERN_C int _gl_cxxalias_dummy
# endif
#else
# define _GL_CXXALIASWARN1(func,rettype,parameters_and_attributes) \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#endif

#endif /* _GL_CXXDEFS_H */

/* The definition of _GL_WARN_ON_USE is copied here.  */
/* A C macro for emitting warnings if a function is used.
   Copyright (C) 2010-2022 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as published
   by the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* _GL_WARN_ON_USE (function, "literal string") issues a declaration
   for FUNCTION which will then trigger a compiler warning containing
   the text of "literal string" anywhere that function is called, if
   supported by the compiler.  If the compiler does not support this
   feature, the macro expands to an unused extern declaration.

   _GL_WARN_ON_USE_ATTRIBUTE ("literal string") expands to the
   attribute used in _GL_WARN_ON_USE.  If the compiler does not support
   this feature, it expands to empty.

   These macros are useful for marking a function as a potential
   portability trap, with the intent that "literal string" include
   instructions on the replacement function that should be used
   instead.
   _GL_WARN_ON_USE is for functions with 'extern' linkage.
   _GL_WARN_ON_USE_ATTRIBUTE is for functions with 'static' or 'inline'
   linkage.

   However, one of the reasons that a function is a portability trap is
   if it has the wrong signature.  Declaring FUNCTION with a different
   signature in C is a compilation error, so this macro must use the
   same type as any existing declaration so that programs that avoid
   the problematic FUNCTION do not fail to compile merely because they
   included a header that poisoned the function.  But this implies that
   _GL_WARN_ON_USE is only safe to use if FUNCTION is known to already
   have a declaration.  Use of this macro implies that there must not
   be any other macro hiding the declaration of FUNCTION; but
   undefining FUNCTION first is part of the poisoning process anyway
   (although for symbols that are provided only via a macro, the result
   is a compilation error rather than a warning containing
   "literal string").  Also note that in C++, it is only safe to use if
   FUNCTION has no overloads.

   For an example, it is possible to poison 'getline' by:
   - adding a call to gl_WARN_ON_USE_PREPARE([[#include <stdio.h>]],
     [getline]) in configure.ac, which potentially defines
     HAVE_RAW_DECL_GETLINE
   - adding this code to a header that wraps the system <stdio.h>:
     #undef getline
     #if HAVE_RAW_DECL_GETLINE
     _GL_WARN_ON_USE (getline, "getline is required by POSIX 2008, but"
       "not universally present; use the gnulib module getline");
     #endif

   It is not possible to directly poison global variables.  But it is
   possible to write a wrapper accessor function, and poison that
   (less common usage, like &environ, will cause a compilation error
   rather than issue the nice warning, but the end result of informing
   the developer about their portability problem is still achieved):
     #if HAVE_RAW_DECL_ENVIRON
     static char ***
     rpl_environ (void) { return &environ; }
     _GL_WARN_ON_USE (rpl_environ, "environ is not always properly declared");
     # undef environ
     # define environ (*rpl_environ ())
     #endif
   or better (avoiding contradictory use of 'static' and 'extern'):
     #if HAVE_RAW_DECL_ENVIRON
     static char ***
     _GL_WARN_ON_USE_ATTRIBUTE ("environ is not always properly declared")
     rpl_environ (void) { return &environ; }
     # undef environ
     # define environ (*rpl_environ ())
     #endif
   */
#ifndef _GL_WARN_ON_USE

# if 4 < __GNUC__ || (__GNUC__ == 4 && 3 <= __GNUC_MINOR__)
/* A compiler attribute is available in gcc versions 4.3.0 and later.  */
#  define _GL_WARN_ON_USE(function, message) \
_GL_WARN_EXTERN_C __typeof__ (function) function __attribute__ ((__warning__ (message)))
#  define _GL_WARN_ON_USE_ATTRIBUTE(message) \
  __attribute__ ((__warning__ (message)))
# elif __clang_major__ >= 4
/* Another compiler attribute is available in clang.  */
#  define _GL_WARN_ON_USE(function, message) \
_GL_WARN_EXTERN_C __typeof__ (function) function \
  __attribute__ ((__diagnose_if__ (1, message, "warning")))
#  define _GL_WARN_ON_USE_ATTRIBUTE(message) \
  __attribute__ ((__diagnose_if__ (1, message, "warning")))
# elif __GNUC__ >= 3 && GNULIB_STRICT_CHECKING
/* Verify the existence of the function.  */
#  define _GL_WARN_ON_USE(function, message) \
_GL_WARN_EXTERN_C __typeof__ (function) function
#  define _GL_WARN_ON_USE_ATTRIBUTE(message)
# else /* Unsupported.  */
#  define _GL_WARN_ON_USE(function, message) \
_GL_WARN_EXTERN_C int _gl_warn_on_use
#  define _GL_WARN_ON_USE_ATTRIBUTE(message)
# endif
#endif

/* _GL_WARN_ON_USE_CXX (function, rettype_gcc, rettype_clang, parameters_and_attributes, "message")
   is like _GL_WARN_ON_USE (function, "message"), except that in C++ mode the
   function is declared with the given prototype, consisting of return type,
   parameters, and attributes.
   This variant is useful for overloaded functions in C++. _GL_WARN_ON_USE does
   not work in this case.  */
#ifndef _GL_WARN_ON_USE_CXX
# if !defined __cplusplus
#  define _GL_WARN_ON_USE_CXX(function,rettype_gcc,rettype_clang,parameters_and_attributes,msg) \
     _GL_WARN_ON_USE (function, msg)
# else
#  if 4 < __GNUC__ || (__GNUC__ == 4 && 3 <= __GNUC_MINOR__)
/* A compiler attribute is available in gcc versions 4.3.0 and later.  */
#   define _GL_WARN_ON_USE_CXX(function,rettype_gcc,rettype_clang,parameters_and_attributes,msg) \
extern rettype_gcc function parameters_and_attributes \
  __attribute__ ((__warning__ (msg)))
#  elif __clang_major__ >= 4
/* Another compiler attribute is available in clang.  */
#   define _GL_WARN_ON_USE_CXX(function,rettype_gcc,rettype_clang,parameters_and_attributes,msg) \
extern rettype_clang function parameters_and_attributes \
  __attribute__ ((__diagnose_if__ (1, msg, "warning")))
#  elif __GNUC__ >= 3 && GNULIB_STRICT_CHECKING
/* Verify the existence of the function.  */
#   define _GL_WARN_ON_USE_CXX(function,rettype_gcc,rettype_clang,parameters_and_attributes,msg) \
extern rettype_gcc function parameters_and_attributes
#  else /* Unsupported.  */
#   define _GL_WARN_ON_USE_CXX(function,rettype_gcc,rettype_clang,parameters_and_attributes,msg) \
_GL_WARN_EXTERN_C int _gl_warn_on_use
#  endif
# endif
#endif

/* _GL_WARN_EXTERN_C declaration;
   performs the declaration with C linkage.  */
#ifndef _GL_WARN_EXTERN_C
# if defined __cplusplus
#  define _GL_WARN_EXTERN_C extern "C"
# else
#  define _GL_WARN_EXTERN_C extern
# endif
#endif


/* Fix some definitions from <winsock2.h>.  */

#if 0

# if !GNULIB_defined_rpl_fd_isset

/* Re-define FD_ISSET to avoid a WSA call while we are not using
   network sockets.  */
static int
rpl_fd_isset (SOCKET fd, fd_set * set)
{
  u_int i;
  if (set == NULL)
    return 0;

  for (i = 0; i < set->fd_count; i++)
    if (set->fd_array[i] == fd)
      return 1;

  return 0;
}

#  define GNULIB_defined_rpl_fd_isset 1
# endif

# undef FD_ISSET
# define FD_ISSET(fd, set) rpl_fd_isset(fd, set)

#endif

/* Hide some function declarations from <winsock2.h>.  */

#if 0
# if !defined _GL_UNISTD_H
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef close
#   define close close_used_without_including_unistd_h
#  elif !defined __clang__
    _GL_WARN_ON_USE (close,
                     "close() used without including <unistd.h>");
#  endif
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef gethostname
#   define gethostname gethostname_used_without_including_unistd_h
#  elif !defined __clang__
    _GL_WARN_ON_USE (gethostname,
                     "gethostname() used without including <unistd.h>");
#  endif
# endif
# if !defined _GL_SYS_SOCKET_H
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef socket
#   define socket              socket_used_without_including_sys_socket_h
#   undef connect
#   define connect             connect_used_without_including_sys_socket_h
#   undef accept
#   define accept              accept_used_without_including_sys_socket_h
#   undef bind
#   define bind                bind_used_without_including_sys_socket_h
#   undef getpeername
#   define getpeername         getpeername_used_without_including_sys_socket_h
#   undef getsockname
#   define getsockname         getsockname_used_without_including_sys_socket_h
#   undef getsockopt
#   define getsockopt          getsockopt_used_without_including_sys_socket_h
#   undef listen
#   define listen              listen_used_without_including_sys_socket_h
#   undef recv
#   define recv                recv_used_without_including_sys_socket_h
#   undef send
#   define send                send_used_without_including_sys_socket_h
#   undef recvfrom
#   define recvfrom            recvfrom_used_without_including_sys_socket_h
#   undef sendto
#   define sendto              sendto_used_without_including_sys_socket_h
#   undef setsockopt
#   define setsockopt          setsockopt_used_without_including_sys_socket_h
#   undef shutdown
#   define shutdown            shutdown_used_without_including_sys_socket_h
#  elif !defined __clang__
    _GL_WARN_ON_USE (socket,
                     "socket() used without including <sys/socket.h>");
    _GL_WARN_ON_USE (connect,
                     "connect() used without including <sys/socket.h>");
    _GL_WARN_ON_USE (accept,
                     "accept() used without including <sys/socket.h>");
    _GL_WARN_ON_USE (bind,
                     "bind() used without including <sys/socket.h>");
    _GL_WARN_ON_USE (getpeername,
                     "getpeername() used without including <sys/socket.h>");
    _GL_WARN_ON_USE (getsockname,
                     "getsockname() used without including <sys/socket.h>");
    _GL_WARN_ON_USE (getsockopt,
                     "getsockopt() used without including <sys/socket.h>");
    _GL_WARN_ON_USE (listen,
                     "listen() used without including <sys/socket.h>");
    _GL_WARN_ON_USE (recv,
                     "recv() used without including <sys/socket.h>");
    _GL_WARN_ON_USE (send,
                     "send() used without including <sys/socket.h>");
    _GL_WARN_ON_USE (recvfrom,
                     "recvfrom() used without including <sys/socket.h>");
    _GL_WARN_ON_USE (sendto,
                     "sendto() used without including <sys/socket.h>");
    _GL_WARN_ON_USE (setsockopt,
                     "setsockopt() used without including <sys/socket.h>");
    _GL_WARN_ON_USE (shutdown,
                     "shutdown() used without including <sys/socket.h>");
#  endif
# endif
#endif


#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef pselect
#   define pselect rpl_pselect
#  endif
_GL_FUNCDECL_RPL (pselect, int,
                  (int, fd_set *restrict, fd_set *restrict, fd_set *restrict,
                   struct timespec const *restrict, const sigset_t *restrict));
_GL_CXXALIAS_RPL (pselect, int,
                  (int, fd_set *restrict, fd_set *restrict, fd_set *restrict,
                   struct timespec const *restrict, const sigset_t *restrict));
# else
#  if !1
_GL_FUNCDECL_SYS (pselect, int,
                  (int, fd_set *restrict, fd_set *restrict, fd_set *restrict,
                   struct timespec const *restrict, const sigset_t *restrict));
#  endif
/* Need to cast, because on AIX 7, the second, third, fourth argument may be
                        void *restrict,   void *restrict,   void *restrict.  */
_GL_CXXALIAS_SYS_CAST (pselect, int,
                       (int,
                        fd_set *restrict, fd_set *restrict, fd_set *restrict,
                        struct timespec const *restrict,
                        const sigset_t *restrict));
# endif
_GL_CXXALIASWARN (pselect);
#elif defined GNULIB_POSIXCHECK
# undef pselect
# if HAVE_RAW_DECL_PSELECT
_GL_WARN_ON_USE (pselect, "pselect is not portable - "
                 "use gnulib module pselect for portability");
# endif
#endif

#if 1
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef select
#   define select rpl_select
#  endif
_GL_FUNCDECL_RPL (select, int,
                  (int, fd_set *restrict, fd_set *restrict, fd_set *restrict,
                   struct timeval *restrict));
_GL_CXXALIAS_RPL (select, int,
                  (int, fd_set *restrict, fd_set *restrict, fd_set *restrict,
                   timeval *restrict));
# else
_GL_CXXALIAS_SYS (select, int,
                  (int, fd_set *restrict, fd_set *restrict, fd_set *restrict,
                   timeval *restrict));
# endif
_GL_CXXALIASWARN (select);
#elif 0
# undef select
# define select select_used_without_requesting_gnulib_module_select
#elif defined GNULIB_POSIXCHECK
# undef select
# if HAVE_RAW_DECL_SELECT
_GL_WARN_ON_USE (select, "select is not always POSIX compliant - "
                 "use gnulib module select for portability");
# endif
#endif


#endif /* _GL_SYS_SELECT_H */
#endif /* _GL_SYS_SELECT_H */
#endif /* OSF/1 */
