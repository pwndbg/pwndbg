/* The date below is automatically updated every day by a bot.  During
   development, we include the date in the tools' version strings
   (visible in 'ld -v' etc.) because people build binutils from a
   variety of sources - git, tarballs, distro sources - and we want
   something that can easily identify the source they used when they
   report bugs.  The bfd version plus date is usually good enough for
   that purpose.

   During development, this date ends up in libbfd and libopcodes
   sonames because people naturally expect shared libraries with the
   same soname to have compatible ABIs.  We could bump the bfd version
   on every ABI change, but that's just another thing contributors and
   maintainers would need to remember.  Instead, it's much easier for
   all if the soname contains the date.  This is not perfect but is
   good enough.

   In releases, the date is not included in either version strings or
   sonames.  */
#define BFD_VERSION_DATE 20251005
#define BFD_VERSION 245500000
#define BFD_VERSION_STRING  "(GNU Binutils) " "2.45.50.20251005"
#define REPORT_BUGS_TO "<https://sourceware.org/bugzilla/>"
