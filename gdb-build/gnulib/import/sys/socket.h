/* DO NOT EDIT! GENERATED AUTOMATICALLY! */
/* Provide a sys/socket header file for systems lacking it (read: MinGW)
   and for systems where it is incomplete.
   Copyright (C) 2005-2022 Free Software Foundation, Inc.
   Written by Simon Josefsson.

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

/* This file is supposed to be used on platforms that lack <sys/socket.h>,
   on platforms where <sys/socket.h> cannot be included standalone, and on
   platforms where <sys/socket.h> does not provide all necessary definitions.
   It is intended to provide definitions and prototypes needed by an
   application.  */

#if __GNUC__ >= 3
#pragma GCC system_header
#endif


#if defined _GL_ALREADY_INCLUDING_SYS_SOCKET_H
/* Special invocation convention:
   - On Cygwin 1.5.x we have a sequence of nested includes
     <sys/socket.h> -> <cygwin/socket.h> -> <asm/socket.h> -> <cygwin/if.h>,
     and the latter includes <sys/socket.h>.  In this situation, the functions
     are not yet declared, therefore we cannot provide the C++ aliases.  */

#include_next <sys/socket.h>

#else
/* Normal invocation convention.  */

#ifndef _GL_SYS_SOCKET_H

#if 1

# define _GL_ALREADY_INCLUDING_SYS_SOCKET_H

/* On many platforms, <sys/socket.h> assumes prior inclusion of
   <sys/types.h>.  */
# include <sys/types.h>

/* On FreeBSD 6.4, <sys/socket.h> defines some macros that assume that NULL
   is defined.  */
# include <stddef.h>

/* The include_next requires a split double-inclusion guard.  */
# include_next <sys/socket.h>

# undef _GL_ALREADY_INCLUDING_SYS_SOCKET_H

#endif

#ifndef _GL_SYS_SOCKET_H
#define _GL_SYS_SOCKET_H

#ifndef _GL_INLINE_HEADER_BEGIN
 #error "Please include config.h first."
#endif
_GL_INLINE_HEADER_BEGIN
#ifndef _GL_SYS_SOCKET_INLINE
# define _GL_SYS_SOCKET_INLINE _GL_INLINE
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

/* The definition of _GL_ARG_NONNULL is copied here.  */
/* A C macro for declaring that specific arguments must not be NULL.
   Copyright (C) 2009-2022 Free Software Foundation, Inc.

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

/* _GL_ARG_NONNULL((n,...,m)) tells the compiler and static analyzer tools
   that the values passed as arguments n, ..., m must be non-NULL pointers.
   n = 1 stands for the first argument, n = 2 for the second argument etc.  */
#ifndef _GL_ARG_NONNULL
# if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 3) || defined __clang__
#  define _GL_ARG_NONNULL(params) __attribute__ ((__nonnull__ params))
# else
#  define _GL_ARG_NONNULL(params)
# endif
#endif

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

#if !1
# if !GNULIB_defined_sa_family_t
/* On OS/2 kLIBC, sa_family_t is unsigned char unless TCPV40HDRS is defined. */
#  if !defined __KLIBC__ || defined TCPV40HDRS
typedef unsigned short  sa_family_t;
#  else
typedef unsigned char   sa_family_t;
#  endif
#  define GNULIB_defined_sa_family_t 1
# endif
#endif

#if 1
/* Make the 'struct sockaddr_storage' field 'ss_family' visible on AIX 7.1.  */
# if !1
#  ifndef ss_family
#   define ss_family __ss_family
#  endif
# endif
#else
# include <stdalign.h>
/* Code taken from glibc sysdeps/unix/sysv/linux/bits/socket.h on
   2009-05-08, licensed under LGPLv2.1+, plus portability fixes. */
# define __ss_aligntype unsigned long int
# define _SS_SIZE 256
# define _SS_PADSIZE \
    (_SS_SIZE - ((sizeof (sa_family_t) >= alignof (__ss_aligntype)      \
                  ? sizeof (sa_family_t)                                \
                  : alignof (__ss_aligntype))                           \
                 + sizeof (__ss_aligntype)))

# if !GNULIB_defined_struct_sockaddr_storage
struct sockaddr_storage
{
  sa_family_t ss_family;      /* Address family, etc.  */
  __ss_aligntype __ss_align;  /* Force desired alignment.  */
  char __ss_padding[_SS_PADSIZE];
};
#  define GNULIB_defined_struct_sockaddr_storage 1
# endif

#endif

/* Get struct iovec.  */
/* But avoid namespace pollution on glibc systems.  */
#if ! defined __GLIBC__
# include <sys/uio.h>
#endif

#if 1

/* A platform that has <sys/socket.h>.  */

/* For shutdown().  */
# if !defined SHUT_RD
#  define SHUT_RD 0
# endif
# if !defined SHUT_WR
#  define SHUT_WR 1
# endif
# if !defined SHUT_RDWR
#  define SHUT_RDWR 2
# endif

# ifdef __VMS                        /* OpenVMS */
#  ifndef CMSG_SPACE
#   define CMSG_SPACE(length) _CMSG_SPACE(length)
#  endif
#  ifndef CMSG_LEN
#   define CMSG_LEN(length) _CMSG_LEN(length)
#  endif
# endif

#else

# ifdef __CYGWIN__
#  error "Cygwin does have a sys/socket.h, doesn't it?!?"
# endif

/* A platform that lacks <sys/socket.h>.

   Currently only MinGW is supported.  See the gnulib manual regarding
   Windows sockets.  MinGW has the header files winsock2.h and
   ws2tcpip.h that declare the sys/socket.h definitions we need.  Note
   that you can influence which definitions you get by setting the
   WINVER symbol before including these two files.  For example,
   getaddrinfo is only available if _WIN32_WINNT >= 0x0501 (that
   symbol is set indirectly through WINVER).  You can set this by
   adding AC_DEFINE(WINVER, 0x0501) to configure.ac.  Note that your
   code may not run on older Windows releases then.  My Windows 2000
   box was not able to run the code, for example.  The situation is
   slightly confusing because
   <https://docs.microsoft.com/en-us/windows/desktop/api/ws2tcpip/nf-ws2tcpip-getaddrinfo>
   suggests that getaddrinfo should be available on all Windows
   releases. */

# if 0
#  include <winsock2.h>
# endif
# if 0
#  include <ws2tcpip.h>
# endif

/* For shutdown(). */
# if !defined SHUT_RD && defined SD_RECEIVE
#  define SHUT_RD SD_RECEIVE
# endif
# if !defined SHUT_WR && defined SD_SEND
#  define SHUT_WR SD_SEND
# endif
# if !defined SHUT_RDWR && defined SD_BOTH
#  define SHUT_RDWR SD_BOTH
# endif

# if 0
/* Include headers needed by the emulation code.  */
#  include <sys/types.h>
#  include <io.h>
/* If these headers don't define socklen_t, <config.h> does.  */
# endif

/* Rudimentary 'struct msghdr'; this works as long as you don't try to
   access msg_control or msg_controllen.  */
struct msghdr {
  void *msg_name;
  socklen_t msg_namelen;
  struct iovec *msg_iov;
  int msg_iovlen;
  int msg_flags;
};

#endif

/* Ensure SO_REUSEPORT is defined.  */
/* For the subtle differences between SO_REUSEPORT and SO_REUSEADDR, see
   https://stackoverflow.com/questions/14388706/socket-options-so-reuseaddr-and-so-reuseport-how-do-they-differ-do-they-mean-t
   and https://lwn.net/Articles/542629/
 */
#ifndef SO_REUSEPORT
# define SO_REUSEPORT SO_REUSEADDR
#endif

/* Fix some definitions from <winsock2.h>.  */

#if 0

# if !GNULIB_defined_rpl_fd_isset

/* Re-define FD_ISSET to avoid a WSA call while we are not using
   network sockets.  */
_GL_SYS_SOCKET_INLINE int
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
#  else
    _GL_WARN_ON_USE (gethostname,
                     "gethostname() used without including <unistd.h>");
#  endif
# endif
# if !defined _GL_SYS_SELECT_H
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef select
#   define select select_used_without_including_sys_select_h
#  else
    _GL_WARN_ON_USE (select,
                     "select() used without including <sys/select.h>");
#  endif
# endif
#endif

/* Wrap everything else to use libc file descriptors for sockets.  */

#if 1
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef socket
#   define socket rpl_socket
#  endif
_GL_FUNCDECL_RPL (socket, int, (int domain, int type, int protocol));
_GL_CXXALIAS_RPL (socket, int, (int domain, int type, int protocol));
# else
_GL_CXXALIAS_SYS (socket, int, (int domain, int type, int protocol));
# endif
_GL_CXXALIASWARN (socket);
#elif 0
# undef socket
# define socket socket_used_without_requesting_gnulib_module_socket
#elif defined GNULIB_POSIXCHECK
# undef socket
# if HAVE_RAW_DECL_SOCKET
_GL_WARN_ON_USE (socket, "socket is not always POSIX compliant - "
                 "use gnulib module socket for portability");
# endif
#endif

#if 1
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef connect
#   define connect rpl_connect
#  endif
_GL_FUNCDECL_RPL (connect, int,
                  (int fd, const struct sockaddr *addr, socklen_t addrlen)
                  _GL_ARG_NONNULL ((2)));
_GL_CXXALIAS_RPL (connect, int,
                  (int fd, const struct sockaddr *addr, socklen_t addrlen));
# else
/* Need to cast, because on NonStop Kernel, the third parameter is
                                                     size_t addrlen.  */
_GL_CXXALIAS_SYS_CAST (connect, int,
                       (int fd,
                        const struct sockaddr *addr, socklen_t addrlen));
# endif
_GL_CXXALIASWARN (connect);
#elif 0
# undef connect
# define connect socket_used_without_requesting_gnulib_module_connect
#elif defined GNULIB_POSIXCHECK
# undef connect
# if HAVE_RAW_DECL_CONNECT
_GL_WARN_ON_USE (connect, "connect is not always POSIX compliant - "
                 "use gnulib module connect for portability");
# endif
#endif

#if 1
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef accept
#   define accept rpl_accept
#  endif
_GL_FUNCDECL_RPL (accept, int,
                  (int fd,
                   struct sockaddr *restrict addr,
                   socklen_t *restrict addrlen));
_GL_CXXALIAS_RPL (accept, int,
                  (int fd,
                   struct sockaddr *restrict addr,
                   socklen_t *restrict addrlen));
# else
/* Need to cast, because on Solaris 10 systems, the third parameter is
                        void *addrlen.  */
_GL_CXXALIAS_SYS_CAST (accept, int,
                       (int fd,
                        struct sockaddr *restrict addr,
                        socklen_t *restrict addrlen));
# endif
_GL_CXXALIASWARN (accept);
#elif 0
# undef accept
# define accept accept_used_without_requesting_gnulib_module_accept
#elif defined GNULIB_POSIXCHECK
# undef accept
# if HAVE_RAW_DECL_ACCEPT
_GL_WARN_ON_USE (accept, "accept is not always POSIX compliant - "
                 "use gnulib module accept for portability");
# endif
#endif

#if 1
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef bind
#   define bind rpl_bind
#  endif
_GL_FUNCDECL_RPL (bind, int,
                  (int fd, const struct sockaddr *addr, socklen_t addrlen)
                  _GL_ARG_NONNULL ((2)));
_GL_CXXALIAS_RPL (bind, int,
                  (int fd, const struct sockaddr *addr, socklen_t addrlen));
# else
/* Need to cast, because on NonStop Kernel, the third parameter is
                                                     size_t addrlen.  */
_GL_CXXALIAS_SYS_CAST (bind, int,
                       (int fd,
                        const struct sockaddr *addr, socklen_t addrlen));
# endif
_GL_CXXALIASWARN (bind);
#elif 0
# undef bind
# define bind bind_used_without_requesting_gnulib_module_bind
#elif defined GNULIB_POSIXCHECK
# undef bind
# if HAVE_RAW_DECL_BIND
_GL_WARN_ON_USE (bind, "bind is not always POSIX compliant - "
                 "use gnulib module bind for portability");
# endif
#endif

#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef getpeername
#   define getpeername rpl_getpeername
#  endif
_GL_FUNCDECL_RPL (getpeername, int,
                  (int fd, struct sockaddr *restrict addr,
                   socklen_t *restrict addrlen)
                  _GL_ARG_NONNULL ((2, 3)));
_GL_CXXALIAS_RPL (getpeername, int,
                  (int fd, struct sockaddr *restrict addr,
                   socklen_t *restrict addrlen));
# else
/* Need to cast, because on Solaris 10 systems, the third parameter is
                        void *addrlen.  */
_GL_CXXALIAS_SYS_CAST (getpeername, int,
                       (int fd, struct sockaddr *restrict addr,
                        socklen_t *restrict addrlen));
# endif
_GL_CXXALIASWARN (getpeername);
#elif 0
# undef getpeername
# define getpeername getpeername_used_without_requesting_gnulib_module_getpeername
#elif defined GNULIB_POSIXCHECK
# undef getpeername
# if HAVE_RAW_DECL_GETPEERNAME
_GL_WARN_ON_USE (getpeername, "getpeername is not always POSIX compliant - "
                 "use gnulib module getpeername for portability");
# endif
#endif

#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef getsockname
#   define getsockname rpl_getsockname
#  endif
_GL_FUNCDECL_RPL (getsockname, int,
                  (int fd, struct sockaddr *restrict addr,
                   socklen_t *restrict addrlen)
                  _GL_ARG_NONNULL ((2, 3)));
_GL_CXXALIAS_RPL (getsockname, int,
                  (int fd, struct sockaddr *restrict addr,
                   socklen_t *restrict addrlen));
# else
/* Need to cast, because on Solaris 10 systems, the third parameter is
                        void *addrlen.  */
_GL_CXXALIAS_SYS_CAST (getsockname, int,
                       (int fd, struct sockaddr *restrict addr,
                        socklen_t *restrict addrlen));
# endif
_GL_CXXALIASWARN (getsockname);
#elif 0
# undef getsockname
# define getsockname getsockname_used_without_requesting_gnulib_module_getsockname
#elif defined GNULIB_POSIXCHECK
# undef getsockname
# if HAVE_RAW_DECL_GETSOCKNAME
_GL_WARN_ON_USE (getsockname, "getsockname is not always POSIX compliant - "
                 "use gnulib module getsockname for portability");
# endif
#endif

#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef getsockopt
#   define getsockopt rpl_getsockopt
#  endif
_GL_FUNCDECL_RPL (getsockopt, int,
                  (int fd, int level, int optname,
                   void *restrict optval, socklen_t *restrict optlen)
                  _GL_ARG_NONNULL ((4, 5)));
_GL_CXXALIAS_RPL (getsockopt, int,
                  (int fd, int level, int optname,
                   void *restrict optval, socklen_t *restrict optlen));
# else
/* Need to cast, because on Solaris 10 systems, the fifth parameter is
                                                       void *optlen.  */
_GL_CXXALIAS_SYS_CAST (getsockopt, int,
                       (int fd, int level, int optname,
                        void *restrict optval, socklen_t *restrict optlen));
# endif
_GL_CXXALIASWARN (getsockopt);
#elif 0
# undef getsockopt
# define getsockopt getsockopt_used_without_requesting_gnulib_module_getsockopt
#elif defined GNULIB_POSIXCHECK
# undef getsockopt
# if HAVE_RAW_DECL_GETSOCKOPT
_GL_WARN_ON_USE (getsockopt, "getsockopt is not always POSIX compliant - "
                 "use gnulib module getsockopt for portability");
# endif
#endif

#if 1
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef listen
#   define listen rpl_listen
#  endif
_GL_FUNCDECL_RPL (listen, int, (int fd, int backlog));
_GL_CXXALIAS_RPL (listen, int, (int fd, int backlog));
# else
_GL_CXXALIAS_SYS (listen, int, (int fd, int backlog));
# endif
_GL_CXXALIASWARN (listen);
#elif 0
# undef listen
# define listen listen_used_without_requesting_gnulib_module_listen
#elif defined GNULIB_POSIXCHECK
# undef listen
# if HAVE_RAW_DECL_LISTEN
_GL_WARN_ON_USE (listen, "listen is not always POSIX compliant - "
                 "use gnulib module listen for portability");
# endif
#endif

#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef recv
#   define recv rpl_recv
#  endif
_GL_FUNCDECL_RPL (recv, ssize_t, (int fd, void *buf, size_t len, int flags)
                                 _GL_ARG_NONNULL ((2)));
_GL_CXXALIAS_RPL (recv, ssize_t, (int fd, void *buf, size_t len, int flags));
# else
/* Need to cast, because on HP-UX 11.31 the return type may be
                             int,
   depending on compiler options.  */
_GL_CXXALIAS_SYS_CAST (recv, ssize_t, (int fd, void *buf, size_t len, int flags));
# endif
_GL_CXXALIASWARN (recv);
#elif 0
# undef recv
# define recv recv_used_without_requesting_gnulib_module_recv
#elif defined GNULIB_POSIXCHECK
# undef recv
# if HAVE_RAW_DECL_RECV
_GL_WARN_ON_USE (recv, "recv is not always POSIX compliant - "
                 "use gnulib module recv for portability");
# endif
#endif

#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef send
#   define send rpl_send
#  endif
_GL_FUNCDECL_RPL (send, ssize_t,
                  (int fd, const void *buf, size_t len, int flags)
                  _GL_ARG_NONNULL ((2)));
_GL_CXXALIAS_RPL (send, ssize_t,
                  (int fd, const void *buf, size_t len, int flags));
# else
/* Need to cast, because on HP-UX 11.31 the return type may be
                             int,
   depending on compiler options.  */
_GL_CXXALIAS_SYS_CAST (send, ssize_t,
                       (int fd, const void *buf, size_t len, int flags));
# endif
_GL_CXXALIASWARN (send);
#elif 0
# undef send
# define send send_used_without_requesting_gnulib_module_send
#elif defined GNULIB_POSIXCHECK
# undef send
# if HAVE_RAW_DECL_SEND
_GL_WARN_ON_USE (send, "send is not always POSIX compliant - "
                 "use gnulib module send for portability");
# endif
#endif

#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef recvfrom
#   define recvfrom rpl_recvfrom
#  endif
_GL_FUNCDECL_RPL (recvfrom, ssize_t,
                  (int fd, void *restrict buf, size_t len, int flags,
                   struct sockaddr *restrict from,
                   socklen_t *restrict fromlen)
                  _GL_ARG_NONNULL ((2)));
_GL_CXXALIAS_RPL (recvfrom, ssize_t,
                  (int fd, void *restrict buf, size_t len, int flags,
                   struct sockaddr *restrict from,
                   socklen_t *restrict fromlen));
# else
/* Need to cast, because on Solaris 10 systems, the sixth parameter is
                                               void *fromlen.  */
_GL_CXXALIAS_SYS_CAST (recvfrom, ssize_t,
                       (int fd, void *restrict buf, size_t len, int flags,
                        struct sockaddr *restrict from,
                        socklen_t *restrict fromlen));
# endif
_GL_CXXALIASWARN (recvfrom);
#elif 0
# undef recvfrom
# define recvfrom recvfrom_used_without_requesting_gnulib_module_recvfrom
#elif defined GNULIB_POSIXCHECK
# undef recvfrom
# if HAVE_RAW_DECL_RECVFROM
_GL_WARN_ON_USE (recvfrom, "recvfrom is not always POSIX compliant - "
                 "use gnulib module recvfrom for portability");
# endif
#endif

#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef sendto
#   define sendto rpl_sendto
#  endif
_GL_FUNCDECL_RPL (sendto, ssize_t,
                  (int fd, const void *buf, size_t len, int flags,
                   const struct sockaddr *to, socklen_t tolen)
                  _GL_ARG_NONNULL ((2)));
_GL_CXXALIAS_RPL (sendto, ssize_t,
                  (int fd, const void *buf, size_t len, int flags,
                   const struct sockaddr *to, socklen_t tolen));
# else
/* Need to cast, because on NonStop Kernel, the sixth parameter is
                                                   size_t tolen.  */
_GL_CXXALIAS_SYS_CAST (sendto, ssize_t,
                       (int fd, const void *buf, size_t len, int flags,
                        const struct sockaddr *to, socklen_t tolen));
# endif
_GL_CXXALIASWARN (sendto);
#elif 0
# undef sendto
# define sendto sendto_used_without_requesting_gnulib_module_sendto
#elif defined GNULIB_POSIXCHECK
# undef sendto
# if HAVE_RAW_DECL_SENDTO
_GL_WARN_ON_USE (sendto, "sendto is not always POSIX compliant - "
                 "use gnulib module sendto for portability");
# endif
#endif

#if 1
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef setsockopt
#   define setsockopt rpl_setsockopt
#  endif
_GL_FUNCDECL_RPL (setsockopt, int, (int fd, int level, int optname,
                                    const void * optval, socklen_t optlen)
                                   _GL_ARG_NONNULL ((4)));
_GL_CXXALIAS_RPL (setsockopt, int, (int fd, int level, int optname,
                                    const void * optval, socklen_t optlen));
# else
/* Need to cast, because on NonStop Kernel, the fifth parameter is
                                             size_t optlen.  */
_GL_CXXALIAS_SYS_CAST (setsockopt, int,
                       (int fd, int level, int optname,
                        const void * optval, socklen_t optlen));
# endif
_GL_CXXALIASWARN (setsockopt);
#elif 0
# undef setsockopt
# define setsockopt setsockopt_used_without_requesting_gnulib_module_setsockopt
#elif defined GNULIB_POSIXCHECK
# undef setsockopt
# if HAVE_RAW_DECL_SETSOCKOPT
_GL_WARN_ON_USE (setsockopt, "setsockopt is not always POSIX compliant - "
                 "use gnulib module setsockopt for portability");
# endif
#endif

#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef shutdown
#   define shutdown rpl_shutdown
#  endif
_GL_FUNCDECL_RPL (shutdown, int, (int fd, int how));
_GL_CXXALIAS_RPL (shutdown, int, (int fd, int how));
# else
_GL_CXXALIAS_SYS (shutdown, int, (int fd, int how));
# endif
_GL_CXXALIASWARN (shutdown);
#elif 0
# undef shutdown
# define shutdown shutdown_used_without_requesting_gnulib_module_shutdown
#elif defined GNULIB_POSIXCHECK
# undef shutdown
# if HAVE_RAW_DECL_SHUTDOWN
_GL_WARN_ON_USE (shutdown, "shutdown is not always POSIX compliant - "
                 "use gnulib module shutdown for portability");
# endif
#endif

#if 0
/* Accept a connection on a socket, with specific opening flags.
   The flags are a bitmask, possibly including O_CLOEXEC (defined in <fcntl.h>)
   and O_TEXT, O_BINARY (defined in "binary-io.h").
   See also the Linux man page at
   <https://www.kernel.org/doc/man-pages/online/pages/man2/accept4.2.html>.  */
# if 1
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   define accept4 rpl_accept4
#  endif
_GL_FUNCDECL_RPL (accept4, int,
                  (int sockfd, struct sockaddr *addr, socklen_t *addrlen,
                   int flags));
_GL_CXXALIAS_RPL (accept4, int,
                  (int sockfd, struct sockaddr *addr, socklen_t *addrlen,
                   int flags));
# else
_GL_FUNCDECL_SYS (accept4, int,
                  (int sockfd, struct sockaddr *addr, socklen_t *addrlen,
                   int flags));
_GL_CXXALIAS_SYS (accept4, int,
                  (int sockfd, struct sockaddr *addr, socklen_t *addrlen,
                   int flags));
# endif
_GL_CXXALIASWARN (accept4);
#elif defined GNULIB_POSIXCHECK
# undef accept4
# if HAVE_RAW_DECL_ACCEPT4
_GL_WARN_ON_USE (accept4, "accept4 is unportable - "
                 "use gnulib module accept4 for portability");
# endif
#endif

_GL_INLINE_HEADER_END

#endif /* _GL_SYS_SOCKET_H */
#endif /* _GL_SYS_SOCKET_H */
#endif
