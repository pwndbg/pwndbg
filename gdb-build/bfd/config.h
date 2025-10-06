/* config.h.  Generated from config.in by configure.  */
/* config.in.  Generated from configure.ac by autoheader.  */

/* Check that config.h is #included before system headers
    (this works only for glibc, but that should be enough).  */
#if defined(__GLIBC__) && !defined(__FreeBSD_kernel__) && !defined(__CONFIG_H__)
#  error config.h must be #included before system headers
#endif
#define __CONFIG_H__ 1

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* Name of host specific core header file to include in elf.c. */
#define CORE_HEADER "hosts/x86-64linux.h"

/* Define to 1 if you want to enable -z separate-code in ELF linker by
   default. */
#define DEFAULT_LD_Z_SEPARATE_CODE 1

/* Define if you want run-time sanity checks. */
#define ENABLE_CHECKING 1

/* Define to 1 if translation of program messages to the user's native
   language is requested. */
/* #undef ENABLE_NLS */

/* Define to 1 if you have the Mac OS X function
   CFLocaleCopyPreferredLanguages in the CoreFoundation framework. */
/* #undef HAVE_CFLOCALECOPYPREFERREDLANGUAGES */

/* Define to 1 if you have the Mac OS X function CFPreferencesCopyAppValue in
   the CoreFoundation framework. */
/* #undef HAVE_CFPREFERENCESCOPYAPPVALUE */

/* Define if the GNU dcgettext() function is already present or preinstalled.
   */
/* #undef HAVE_DCGETTEXT */

/* Define to 1 if you have the declaration of `asprintf', and to 0 if you
   don't. */
#define HAVE_DECL_ASPRINTF 1

/* Define to 1 if you have the declaration of `basename', and to 0 if you
   don't. */
#define HAVE_DECL_BASENAME 1

/* Define to 1 if you have the declaration of `ffs', and to 0 if you don't. */
#define HAVE_DECL_FFS 1

/* Define to 1 if you have the declaration of `fopen64', and to 0 if you
   don't. */
#define HAVE_DECL_FOPEN64 1

/* Define to 1 if you have the declaration of `fseeko', and to 0 if you don't.
   */
#define HAVE_DECL_FSEEKO 1

/* Define to 1 if you have the declaration of `fseeko64', and to 0 if you
   don't. */
#define HAVE_DECL_FSEEKO64 1

/* Define to 1 if you have the declaration of `ftello', and to 0 if you don't.
   */
#define HAVE_DECL_FTELLO 1

/* Define to 1 if you have the declaration of `ftello64', and to 0 if you
   don't. */
#define HAVE_DECL_FTELLO64 1

/* Define to 1 if you have the declaration of `stpcpy', and to 0 if you don't.
   */
#define HAVE_DECL_STPCPY 1

/* Define to 1 if you have the declaration of `strnlen', and to 0 if you
   don't. */
#define HAVE_DECL_STRNLEN 1

/* Define to 1 if you have the declaration of `vasprintf', and to 0 if you
   don't. */
#define HAVE_DECL_VASPRINTF 1

/* Define to 1 if you have the declaration of `___lc_codepage_func', and to 0
   if you don't. */
#define HAVE_DECL____LC_CODEPAGE_FUNC 0

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the `fcntl' function. */
#define HAVE_FCNTL 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the `fdopen' function. */
#define HAVE_FDOPEN 1

/* Define to 1 if you have the `fileno' function. */
#define HAVE_FILENO 1

/* Define to 1 if you have the `fls' function. */
/* #undef HAVE_FLS */

/* Define to 1 if you have the `fopen64' function. */
#define HAVE_FOPEN64 1

/* Define to 1 if you have the `fseeko' function. */
#define HAVE_FSEEKO 1

/* Define to 1 if you have the `fseeko64' function. */
#define HAVE_FSEEKO64 1

/* Define to 1 if you have the `ftello' function. */
#define HAVE_FTELLO 1

/* Define to 1 if you have the `ftello64' function. */
#define HAVE_FTELLO64 1

/* Define to 1 if you have the `getgid' function. */
#define HAVE_GETGID 1

/* Define to 1 if you have the `getpagesize' function. */
#define HAVE_GETPAGESIZE 1

/* Define to 1 if you have the `getrlimit' function. */
#define HAVE_GETRLIMIT 1

/* Define if the GNU gettext() function is already present or preinstalled. */
/* #undef HAVE_GETTEXT */

/* Define to 1 if you have the `getuid' function. */
#define HAVE_GETUID 1

/* Define if your compiler supports hidden visibility. */
#define HAVE_HIDDEN 1

/* Define if you have the iconv() function and it works. */
/* #undef HAVE_ICONV */

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define if <sys/procfs.h> has lwpstatus_t. */
/* #undef HAVE_LWPSTATUS_T */

/* Define if <sys/procfs.h> has lwpstatus_t.pr_context. */
/* #undef HAVE_LWPSTATUS_T_PR_CONTEXT */

/* Define if <sys/procfs.h> has lwpstatus_t.pr_fpreg. */
/* #undef HAVE_LWPSTATUS_T_PR_FPREG */

/* Define if <sys/procfs.h> has lwpstatus_t.pr_reg. */
/* #undef HAVE_LWPSTATUS_T_PR_REG */

/* Define if <sys/procfs.h> has lwpxstatus_t. */
/* #undef HAVE_LWPXSTATUS_T */

/* Define to 1 if you have the `madvise' function. */
#define HAVE_MADVISE 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have a working `mmap' system call. */
#define HAVE_MMAP 1

/* Define to 1 if you have the `mprotect' function. */
#define HAVE_MPROTECT 1

/* Define if <sys/procfs.h> has prpsinfo32_t. */
/* #undef HAVE_PRPSINFO32_T */

/* Define if <sys/procfs.h> has prpsinfo32_t.pr_pid. */
/* #undef HAVE_PRPSINFO32_T_PR_PID */

/* Define if <sys/procfs.h> has prpsinfo_t. */
#define HAVE_PRPSINFO_T 1

/* Define if <sys/procfs.h> has prpsinfo_t.pr_pid. */
#define HAVE_PRPSINFO_T_PR_PID 1

/* Define if <sys/procfs.h> has prstatus32_t. */
/* #undef HAVE_PRSTATUS32_T */

/* Define if <sys/procfs.h> has prstatus32_t.pr_who. */
/* #undef HAVE_PRSTATUS32_T_PR_WHO */

/* Define if <sys/procfs.h> has prstatus_t. */
#define HAVE_PRSTATUS_T 1

/* Define if <sys/procfs.h> has prstatus_t.pr_who. */
/* #undef HAVE_PRSTATUS_T_PR_WHO */

/* Define if <sys/procfs.h> has psinfo32_t. */
/* #undef HAVE_PSINFO32_T */

/* Define if <sys/procfs.h> has psinfo32_t.pr_pid. */
/* #undef HAVE_PSINFO32_T_PR_PID */

/* Define if <sys/procfs.h> has psinfo_t. */
/* #undef HAVE_PSINFO_T */

/* Define if <sys/procfs.h> has psinfo_t.pr_pid. */
/* #undef HAVE_PSINFO_T_PR_PID */

/* Define if <sys/procfs.h> has pstatus32_t. */
/* #undef HAVE_PSTATUS32_T */

/* Define if <sys/procfs.h> has pstatus_t. */
/* #undef HAVE_PSTATUS_T */

/* Define if <sys/procfs.h> has pxstatus_t. */
/* #undef HAVE_PXSTATUS_T */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define if struct core_dumpx has member c_impl */
/* #undef HAVE_ST_C_IMPL */

/* Define to 1 if you have the `sysconf' function. */
#define HAVE_SYSCONF 1

/* Define to 1 if you have the <sys/file.h> header file. */
#define HAVE_SYS_FILE_H 1

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/procfs.h> header file. */
#define HAVE_SYS_PROCFS_H 1

/* Define to 1 if you have the <sys/resource.h> header file. */
#define HAVE_SYS_RESOURCE_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define if <sys/procfs.h> has win32_pstatus_t. */
/* #undef HAVE_WIN32_PSTATUS_T */

/* Define to 1 if you have the <windows.h> header file. */
/* #undef HAVE_WINDOWS_H */

/* Define to 1 if zstd is enabled. */
#define HAVE_ZSTD 1

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Name of package */
#define PACKAGE "bfd"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "bfd"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "bfd 2.45.50"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "bfd"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "2.45.50"

/* The size of `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of `long', as computed by sizeof. */
#define SIZEOF_LONG 8

/* The size of `long long', as computed by sizeof. */
#define SIZEOF_LONG_LONG 8

/* The size of `off_t', as computed by sizeof. */
#define SIZEOF_OFF_T 8

/* The size of `void *', as computed by sizeof. */
#define SIZEOF_VOID_P 8

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* If the compiler supports a TLS storage class, define it to that here */
#define TLS _Thread_local

/* Name of host specific header file to include in trad-core.c. */
/* #undef TRAD_HEADER */

/* Define if 64-bit archives should always be used. */
/* #undef USE_64_BIT_ARCHIVE */

/* Use b modifier when opening binary files? */
/* #undef USE_BINARY_FOPEN */

/* Define if we should use leading underscore on 64 bit mingw targets */
/* #undef USE_MINGW64_LEADING_UNDERSCORES */

/* Use mmap if it's available? */
#define USE_MMAP 1

/* Define if we should default to creating read-only plt entries */
#define USE_SECUREPLT 1

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif


/* Version number of package */
#define VERSION "2.45.50"

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Enable large inode numbers on Mac OS X 10.5.  */
#ifndef _DARWIN_USE_64_BIT_INODE
# define _DARWIN_USE_64_BIT_INODE 1
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define to 1 if on MINIX. */
/* #undef _MINIX */

/* Define to 2 if the system does not provide POSIX.1 features except with
   this defined. */
/* #undef _POSIX_1_SOURCE */

/* Define to 1 if you need to in order for `stat' and other things to work. */
/* #undef _POSIX_SOURCE */

/* Use structured /proc on Solaris. */
#define _STRUCTURED_PROC 1
