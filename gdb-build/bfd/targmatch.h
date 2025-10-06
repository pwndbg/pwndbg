#ifdef BFD64
#if !defined (SELECT_VECS) || defined (HAVE_aarch64_mach_o_vec)

{ "aarch64-*-darwin*",
&aarch64_mach_o_vec },
#endif




    
#if !defined (SELECT_VECS) || defined (HAVE_aarch64_elf64_le_vec)

{ "aarch64-*-elf", NULL },{ "aarch64-*-rtems*", NULL },{ "aarch64-*-genode*",
&aarch64_elf64_le_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_aarch64_pe_le_vec)

{ "aarch64-*-pe*", NULL },{ "aarch64-*-mingw*",
&aarch64_pe_le_vec },
#endif




    
#if !defined (SELECT_VECS) || defined (HAVE_aarch64_elf64_be_vec)

{ "aarch64_be-*-elf",
&aarch64_elf64_be_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_aarch64_elf64_le_vec)

{ "aarch64-*-freebsd*",
&aarch64_elf64_le_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_aarch64_elf64_le_vec)

{ "aarch64-*-openbsd*",
&aarch64_elf64_le_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_aarch64_elf64_le_vec)

{ "aarch64-*-fuchsia*",
&aarch64_elf64_le_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_aarch64_elf64_le_vec)

{ "aarch64-*-haiku*",
&aarch64_elf64_le_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_aarch64_elf64_le_vec)

{ "aarch64-*-linux*", NULL },{ "aarch64-*-netbsd*", NULL },{ "aarch64-*-nto*", NULL },{ "aarch64-*-gnu*",
&aarch64_elf64_le_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_aarch64_elf64_be_vec)

{ "aarch64_be-*-linux*", NULL },{ "aarch64_be-*-netbsd*",
&aarch64_elf64_be_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_alpha_elf64_fbsd_vec)

{ "alpha*-*-freebsd*", NULL },{ "alpha*-*-kfreebsd*-gnu",
&alpha_elf64_fbsd_vec },
#endif




    
#if !defined (SELECT_VECS) || defined (HAVE_alpha_elf64_vec)

{ "alpha*-*-netbsd*", NULL },{ "alpha*-*-openbsd*",
&alpha_elf64_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_alpha_ecoff_le_vec)

{ "alpha*-*-linux*ecoff*",
&alpha_ecoff_le_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_alpha_elf64_vec)

{ "alpha*-*-linux-*", NULL },{ "alpha*-*-elf*",
&alpha_elf64_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_alpha_vms_vec)

{ "alpha*-*-*vms*",
&alpha_vms_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_alpha_ecoff_le_vec)

{ "alpha*-*-*",
&alpha_ecoff_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_amdgcn_elf64_le_vec)

{ "amdgcn-*-*",
&amdgcn_elf64_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_ia64_elf64_le_vec)

{ "ia64*-*-freebsd*", NULL },{ "ia64*-*-netbsd*", NULL },{ "ia64*-*-linux-*", NULL },{ "ia64*-*-elf*", NULL },{ "ia64*-*-kfreebsd*-gnu",
&ia64_elf64_le_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_ia64_elf32_hpux_be_vec)

{ "ia64*-*-hpux*",
&ia64_elf32_hpux_be_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_ia64_elf64_vms_vec)

{ "ia64*-*-*vms*",
&ia64_elf64_vms_vec },
#endif



    
#endif /* BFD64 */

#if !defined (SELECT_VECS) || defined (HAVE_am33_elf32_linux_vec)

{ "am33_2.0-*-linux*",
&am33_elf32_linux_vec },
#endif

    

#if !defined (SELECT_VECS) || defined (HAVE_arc_elf32_be_vec)

{ "arc*eb-*-elf*", NULL },{ "arc*eb-*-linux*",
&arc_elf32_be_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_arc_elf32_le_vec)

{ "arc*-*-elf*", NULL },{ "arc*-*-linux*",
&arc_elf32_le_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_arm_mach_o_vec)

{ "arm-*-darwin*",
&arm_mach_o_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_arm_elf32_le_vec)

{ "arm-*-fuchsia*",
&arm_elf32_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_arm_elf32_le_vec)

{ "arm*-*-haiku*",
&arm_elf32_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_arm_elf32_be_vec)

{ "armeb-*-netbsd*",
&arm_elf32_be_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_arm_elf32_le_vec)

{ "arm-*-netbsd*", NULL },{ "arm-*-openbsd*",
&arm_elf32_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_arm_elf32_le_vec)

{ "arm-*-nto*", NULL },{ "nto*arm*",
&arm_elf32_le_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_arm_pe_wince_le_vec)

{ "arm-wince-pe", NULL },{ "arm-*-wince", NULL },{ "arm*-*-mingw32ce*", NULL },{ "arm*-*-cegcc*",
&arm_pe_wince_le_vec },
#endif




    
#if !defined (SELECT_VECS) || defined (HAVE_arm_pe_le_vec)

{ "arm-*-pe*",
&arm_pe_le_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_arm_elf32_le_vec)

{ "arm-*-phoenix*",
&arm_elf32_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_arm_elf32_be_vec)

{ "armeb-*-elf", NULL },{ "arm*b-*-freebsd*", NULL },{ "arm*b-*-linux-*", NULL },{ "armeb-*-eabi*",
&arm_elf32_be_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_arm_elf32_le_vec)

{ "arm-*-kaos*",
&arm_elf32_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_arm_elf32_le_vec)

{ "arm-*-elf", NULL },{ "arm*-*-freebsd*", NULL },{ "arm*-*-linux-*", NULL },{ "arm*-*-conix*", NULL },
{ "arm*-*-uclinux*", NULL },{ "arm-*-kfreebsd*-gnu", NULL },
{ "arm*-*-eabi*", NULL },{ "arm-*-rtems*", NULL },{ "arm*-*-uclinuxfdpiceabi",
&arm_elf32_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_arm_elf32_vxworks_le_vec)

{ "arm*-*-vxworks", NULL },{ "arm*-*-windiss",
&arm_elf32_vxworks_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_arm_elf32_le_vec)

{ "arm9e-*-elf",
&arm_elf32_le_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_avr_elf32_vec)

{ "avr-*-*",
&avr_elf32_vec },
#endif

    

#if !defined (SELECT_VECS) || defined (HAVE_bfin_elf32_vec)

{ "bfin-*-*",
&bfin_elf32_vec },
#endif



    

#if !defined (SELECT_VECS) || defined (HAVE_tic30_coff_vec)

{ "c30-*-*coff*", NULL },{ "tic30-*-*coff*",
&tic30_coff_vec },
#endif

    

#if !defined (SELECT_VECS) || defined (HAVE_tic4x_coff1_vec)

{ "c4x-*-*coff*", NULL },{ "tic4x-*-*coff*",
&tic4x_coff1_vec },
#endif



    

#if !defined (SELECT_VECS) || defined (HAVE_tic54x_coff1_vec)

{ "c54x*-*-*coff*", NULL },{ "tic54x-*-*coff*",
&tic54x_coff1_vec },
#endif



    

#if !defined (SELECT_VECS) || defined (HAVE_cr16_elf32_vec)

{ "cr16-*-elf*", NULL },{ "cr16*-*-uclinux*",
&cr16_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_cris_aout_vec)

{ "cris-*-*", NULL },{ "crisv32-*-*",
&cris_aout_vec },
#endif



    

#if !defined (SELECT_VECS) || defined (HAVE_crx_elf32_vec)

{ "crx-*-elf*",
&crx_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_csky_elf32_le_vec)

{ "csky-*-elf*", NULL },{ "csky-*-linux*",
&csky_elf32_le_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_d10v_elf32_vec)

{ "d10v-*-*",
&d10v_elf32_vec },
#endif

    

#if !defined (SELECT_VECS) || defined (HAVE_dlx_elf32_be_vec)

{ "dlx-*-elf*",
&dlx_elf32_be_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_d30v_elf32_vec)

{ "d30v-*-*",
&d30v_elf32_vec },
#endif

    

#ifdef BFD64
#if !defined (SELECT_VECS) || defined (HAVE_bpf_elf64_le_vec)

{ "bpf-*-none",
&bpf_elf64_le_vec },
#endif



    
#endif

#if !defined (SELECT_VECS) || defined (HAVE_epiphany_elf32_vec)

{ "epiphany-*-*",
&epiphany_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_m68k_elf32_vec)

{ "fido-*-elf*",
&m68k_elf32_vec },
#endif

    

#if !defined (SELECT_VECS) || defined (HAVE_fr30_elf32_vec)

{ "fr30-*-elf",
&fr30_elf32_vec },
#endif

    

#if !defined (SELECT_VECS) || defined (HAVE_frv_elf32_vec)

{ "frv-*-elf",
&frv_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_frv_elf32_fdpic_vec)

{ "frv-*-*linux*",
&frv_elf32_fdpic_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_moxie_elf32_be_vec)

{ "moxie-*-elf", NULL },{ "moxie-*-rtems*", NULL },{ "moxie-*-uclinux",
&moxie_elf32_be_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_moxie_elf32_le_vec)

{ "moxie-*-moxiebox*",
&moxie_elf32_le_vec },
#endif

    

#if !defined (SELECT_VECS) || defined (HAVE_h8300_elf32_vec)

{ "h8300*-*-elf", NULL },{ "h8300*-*-rtems*",
&h8300_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_h8300_elf32_linux_vec)

{ "h8300*-*-linux*",
&h8300_elf32_linux_vec },
#endif

    

#ifdef BFD64
#if !defined (SELECT_VECS) || defined (HAVE_hppa_elf64_linux_vec)

{ "hppa*64*-*-linux-*",
&hppa_elf64_linux_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_hppa_elf64_vec)

{ "hppa*64*-*-hpux11*",
&hppa_elf64_vec },
#endif




    
#endif

#if !defined (SELECT_VECS) || defined (HAVE_hppa_elf32_linux_vec)

{ "hppa*-*-linux-*",
&hppa_elf32_linux_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_hppa_elf32_nbsd_vec)

{ "hppa*-*-netbsd*",
&hppa_elf32_nbsd_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_hppa_elf32_vec)

{ "hppa*-*-*elf*", NULL },{ "hppa*-*-lites*", NULL },{ "hppa*-*-sysv4*", NULL },{ "hppa*-*-openbsd*",
&hppa_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_hppa_som_vec)

{ "hppa*-*-bsd*",
&hppa_som_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_hppa_som_vec)

{ "hppa*-*-hpux*", NULL },{ "hppa*-*-hiux*", NULL },{ "hppa*-*-mpeix*",
&hppa_som_vec },
#endif

    
#if !defined (SELECT_VECS) || defined (HAVE_hppa_som_vec)

{ "hppa*-*-osf*",
&hppa_som_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_vec)

{ "i[3-7]86-*-elf*", NULL },{ "i[3-7]86-*-rtems*", NULL },{ "i[3-7]86-*-genode*",
&i386_elf32_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_sol2_vec)

{ "i[3-7]86-*-solaris2*",
&i386_elf32_sol2_vec },
#endif




    
#ifdef BFD64
#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_sol2_vec)

{ "x86_64-*-solaris2*",
&i386_elf32_sol2_vec },
#endif



    
#endif
#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_vec)

{ "i[3-7]86-*-nto*",
&i386_elf32_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_vec)

{ "i[3-7]86-*-aros*",
&i386_elf32_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_vec)

{ "i[3-7]86-*-dicos*",
&i386_elf32_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_i386_coff_go32_vec)

{ "*-*-msdosdjgpp*", NULL },{ "*-*-go32*",
&i386_coff_go32_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_i386_mach_o_vec)

{ "i[3-7]86-*-darwin*", NULL },{ "i[3-7]86-*-macos10*", NULL },{ "i[3-7]86-*-rhapsody*",
&i386_mach_o_vec },
#endif




    
#if !defined (SELECT_VECS) || defined (HAVE_i386_aout_bsd_vec)

{ "i[3-7]86-*-bsd*",
&i386_aout_bsd_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_vec)

{ "i[3-7]86-*-dragonfly*",
&i386_elf32_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_fbsd_vec)

{ "i[3-7]86-*-freebsd*", NULL },{ "i[3-7]86-*-kfreebsd*-gnu",
&i386_elf32_fbsd_vec },
#endif




    
#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_vec)

{ "i[3-7]86-*-netbsd*", NULL },{ "i[3-7]86-*-knetbsd*-gnu",
&i386_elf32_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_vec)

{ "i[3-7]86-*-openbsd*",
&i386_elf32_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_vec)

{ "i[3-7]86-*-linux-*",
&i386_elf32_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_vec)

{ "i[3-7]86-*-redox*",
&i386_elf32_vec },
#endif



    
#ifdef BFD64
#if !defined (SELECT_VECS) || defined (HAVE_x86_64_mach_o_vec)

{ "x86_64-*-darwin*",
&x86_64_mach_o_vec },
#endif




    
#if !defined (SELECT_VECS) || defined (HAVE_x86_64_elf64_vec)

{ "x86_64-*-dicos*",
&x86_64_elf64_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_x86_64_elf64_vec)

{ "x86_64-*-elf*", NULL },{ "x86_64-*-rtems*", NULL },{ "x86_64-*-fuchsia", NULL },{ "x86_64-*-genode*",
&x86_64_elf64_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_x86_64_elf64_vec)

{ "x86_64-*-dragonfly*",
&x86_64_elf64_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_x86_64_elf64_fbsd_vec)

{ "x86_64-*-freebsd*", NULL },{ "x86_64-*-kfreebsd*-gnu",
&x86_64_elf64_fbsd_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_x86_64_elf64_vec)

{ "x86_64-*-haiku*",
&x86_64_elf64_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_x86_64_elf64_vec)

{ "x86_64-*-netbsd*", NULL },{ "x86_64-*-openbsd*",
&x86_64_elf64_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_x86_64_elf64_vec)

{ "x86_64-*-linux-*",
&x86_64_elf64_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_x86_64_pe_vec)

{ "x86_64-*-mingw*", NULL },{ "x86_64-*-pe", NULL },{ "x86_64-*-pep", NULL },{ "x86_64-*-cygwin",
&x86_64_pe_vec },
#endif




    
#if !defined (SELECT_VECS) || defined (HAVE_x86_64_elf64_vec)

{ "x86_64-*-rdos*",
&x86_64_elf64_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_x86_64_elf64_vec)

{ "x86_64-*-redox*",
&x86_64_elf64_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_x86_64_elf64_vec)

{ "x86_64-*-gnu*",
&x86_64_elf64_vec },
#endif



    
#endif
#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_vec)

{ "i[3-7]86-*-lynxos*",
&i386_elf32_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_vec)

{ "i[3-7]86-*-gnu*",
&i386_elf32_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_i386_aout_vec)

{ "i[3-7]86-*-msdos*",
&i386_aout_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_vec)

{ "i[3-7]86-*-moss*",
&i386_elf32_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_i386_pe_vec)

{ "i[3-7]86-*-beospe*",
&i386_pe_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_vec)

{ "i[3-7]86-*-beos*",
&i386_elf32_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_vec)

{ "i[3-7]86-*-haiku*",
&i386_elf32_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_i386_pei_vec)

{ "i[3-7]86-*-interix*",
&i386_pei_vec },
#endif




    
#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_vec)

{ "i[3-7]86-*-rdos*",
&i386_elf32_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_i386_pe_vec)

{ "i[3-7]86-*-mingw32*", NULL },{ "i[3-7]86-*-cygwin*", NULL },{ "i[3-7]86-*-winnt", NULL },{ "i[3-7]86-*-pe",
&i386_pe_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_vxworks_vec)

{ "i[3-7]86-*-vxworks*",
&i386_elf32_vxworks_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_i386_elf32_vec)

{ "ia16-*-elf",
&i386_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_ip2k_elf32_vec)

{ "ip2k-*-elf",
&ip2k_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_iq2000_elf32_vec)

{ "iq2000-*-elf",
&iq2000_elf32_vec },
#endif

    

#ifdef BFD64
#if !defined (SELECT_VECS) || defined (HAVE_kvx_elf64_vec)

{ "kvx-*-linux*",
&kvx_elf64_vec },
#endif



    

#if !defined (SELECT_VECS) || defined (HAVE_kvx_elf64_vec)

{ "kvx-*-*",
&kvx_elf64_vec },
#endif



    
#endif

#if !defined (SELECT_VECS) || defined (HAVE_lm32_elf32_vec)

{ "lm32-*-elf", NULL },{ "lm32-*-rtems*",
&lm32_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_lm32_elf32_fdpic_vec)

{ "lm32-*-*linux*",
&lm32_elf32_fdpic_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_m32c_elf32_vec)

{ "m32c-*-elf",
&m32c_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_m32r_elf32_linux_le_vec)

{ "m32r*le-*-linux*",
&m32r_elf32_linux_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_m32r_elf32_linux_vec)

{ "m32r*-*-linux*",
&m32r_elf32_linux_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_m32r_elf32_le_vec)

{ "m32r*le-*-*",
&m32r_elf32_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_m32r_elf32_vec)

{ "m32r-*-*",
&m32r_elf32_vec },
#endif

    

#if !defined (SELECT_VECS) || defined (HAVE_m68k_elf32_vec)

{ "m68*-*-haiku*",
&m68k_elf32_vec },
#endif

    
#if !defined (SELECT_VECS) || defined (HAVE_m68hc11_elf32_vec)

{ "m68hc11-*-*", NULL },{ "m6811-*-*",
&m68hc11_elf32_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_m68hc12_elf32_vec)

{ "m68hc12-*-*", NULL },{ "m6812-*-*",
&m68hc12_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_m68k_elf32_vec)

{ "m68*-*-*",
&m68k_elf32_vec },
#endif

    

#if !defined (SELECT_VECS) || defined (HAVE_s12z_elf32_vec)

{ "s12z-*-*",
&s12z_elf32_vec },
#endif

    
#if !defined (SELECT_VECS) || defined (HAVE_mcore_elf32_be_vec)

{ "mcore-*-elf",
&mcore_elf32_be_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mcore_pe_be_vec)

{ "mcore-*-pe",
&mcore_pe_be_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_mep_elf32_vec)

{ "mep-*-elf",
&mep_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_metag_elf32_vec)

{ "metag-*-*",
&metag_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_microblaze_elf32_le_vec)

{ "microblazeel*-*",
&microblaze_elf32_le_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_microblaze_elf32_vec)

{ "microblaze*-*",
&microblaze_elf32_vec },
#endif


    

#ifdef BFD64
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_trad_le_vec)

{ "mips*el-*-netbsd*",
&mips_elf32_trad_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_trad_be_vec)

{ "mips*-*-netbsd*",
&mips_elf32_trad_be_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_le_vec)

{ "mips*el-*-haiku*",
&mips_elf32_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_n_be_vec)

{ "mips*-*-irix6*",
&mips_elf32_n_be_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_n_le_vec)

{ "mips64*-ps2-elf*",
&mips_elf32_n_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_le_vec)

{ "mips*-ps2-elf*",
&mips_elf32_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_be_vec)

{ "mips*-*-irix5*",
&mips_elf32_be_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_vxworks_le_vec)

{ "mips*el-*-vxworks*",
&mips_elf32_vxworks_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_vxworks_be_vec)

{ "mips*-*-vxworks*",
&mips_elf32_vxworks_be_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_trad_le_vec)

{ "mips*el-sde-elf*",
&mips_elf32_trad_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_trad_be_vec)

{ "mips*-sde-elf*", NULL },{ "mips*-mti-elf*", NULL },{ "mips*-img-elf*",
&mips_elf32_trad_be_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_le_vec)

{ "mips*el-*-elf*", NULL },{ "mips*-*-chorus*",
&mips_elf32_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_be_vec)

{ "mips*-*-elf*", NULL },{ "mips*-*-rtems*", NULL },{ "mips*-*-windiss", NULL },{ "mips*-*-none",
&mips_elf32_be_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf64_trad_be_vec)

{ "mips64*-*-openbsd*",
&mips_elf64_trad_be_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_le_vec)

{ "mips*el-*-openbsd*",
&mips_elf32_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_be_vec)

{ "mips*-*-openbsd*",
&mips_elf32_be_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf64_trad_le_vec)

{ "mips64*el-*-linux*-gnuabi64",
&mips_elf64_trad_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_ntrad_le_vec)

{ "mips64*el-*-linux*",
&mips_elf32_ntrad_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf64_trad_be_vec)

{ "mips64*-*-linux*-gnuabi64",
&mips_elf64_trad_be_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_ntrad_be_vec)

{ "mips64*-*-linux*",
&mips_elf32_ntrad_be_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_trad_le_vec)

{ "mips*el-*-linux*",
&mips_elf32_trad_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_trad_be_vec)

{ "mips*-*-linux*",
&mips_elf32_trad_be_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_ntradfbsd_le_vec)

{ "mips64*el-*-freebsd*", NULL },{ "mips64*el-*-kfreebsd*-gnu",
&mips_elf32_ntradfbsd_le_vec },
#endif




    

#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_ntradfbsd_be_vec)

{ "mips64*-*-freebsd*", NULL },{ "mips64*-*-kfreebsd*-gnu",
&mips_elf32_ntradfbsd_be_vec },
#endif




    

#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_tradfbsd_le_vec)

{ "mips*el-*-freebsd*", NULL },{ "mips*el-*-kfreebsd*-gnu",
&mips_elf32_tradfbsd_le_vec },
#endif




    

#if !defined (SELECT_VECS) || defined (HAVE_mips_elf32_tradfbsd_be_vec)

{ "mips*-*-freebsd*", NULL },{ "mips*-*-kfreebsd*-gnu",
&mips_elf32_tradfbsd_be_vec },
#endif




    
#if !defined (SELECT_VECS) || defined (HAVE_mmix_elf64_vec)

{ "mmix-*-*",
&mmix_elf64_vec },
#endif



    
#endif
#if !defined (SELECT_VECS) || defined (HAVE_mn10200_elf32_vec)

{ "mn10200-*-*",
&mn10200_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_mn10300_elf32_vec)

{ "mn10300-*-*",
&mn10300_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_mt_elf32_vec)

{ "mt-*-elf",
&mt_elf32_vec },
#endif

    

#if !defined (SELECT_VECS) || defined (HAVE_msp430_elf32_vec)

{ "msp430-*-*",
&msp430_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_nds32_elf32_linux_le_vec)

{ "nds32*le-*-linux*",
&nds32_elf32_linux_le_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_nds32_elf32_linux_be_vec)

{ "nds32*be-*-linux*",
&nds32_elf32_linux_be_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_nds32_elf32_le_vec)

{ "nds32*le-*-*",
&nds32_elf32_le_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_nds32_elf32_be_vec)

{ "nds32*be-*-*",
&nds32_elf32_be_vec },
#endif


    

#ifdef BFD64
#if !defined (SELECT_VECS) || defined (HAVE_nfp_elf64_vec)

{ "nfp-*-*",
&nfp_elf64_vec },
#endif

    
#endif

#if !defined (SELECT_VECS) || defined (HAVE_ns32k_aout_pc532mach_vec)

{ "ns32k-pc532-mach*", NULL },{ "ns32k-pc532-ux*",
&ns32k_aout_pc532mach_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_ns32k_aout_pc532nbsd_vec)

{ "ns32k-*-lites*", NULL },{ "ns32k-*-*bsd*",
&ns32k_aout_pc532nbsd_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_or1k_elf32_vec)

{ "or1k-*-elf", NULL },{ "or1k-*-linux*", NULL },{ "or1k-*-rtems*",
&or1k_elf32_vec },
#endif

    

#if !defined (SELECT_VECS) || defined (HAVE_or1k_elf32_vec)

{ "or1knd-*-elf", NULL },{ "or1knd-*-linux*", NULL },{ "or1knd-*-rtems*",
&or1k_elf32_vec },
#endif

    

#if !defined (SELECT_VECS) || defined (HAVE_pdp11_aout_vec)

{ "pdp11-*-*",
&pdp11_aout_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_pj_elf32_vec)

{ "pj-*-*",
&pj_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_pj_elf32_le_vec)

{ "pjl-*-*",
&pj_elf32_le_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_rs6000_xcoff_vec)

{ "powerpc-*-aix5.[01]", NULL },{ "rs6000-*-aix5.[01]",
&rs6000_xcoff_vec },
#endif



    

#if !defined (SELECT_VECS) || defined (HAVE_rs6000_xcoff_vec)

{ "powerpc-*-aix[5-9]*", NULL },{ "rs6000-*-aix[5-9]*",
&rs6000_xcoff_vec },
#endif



    
#ifdef BFD64
#if !defined (SELECT_VECS) || defined (HAVE_rs6000_xcoff64_aix_vec)

{ "powerpc64-*-aix5.[01]",
&rs6000_xcoff64_aix_vec },
#endif



    

#if !defined (SELECT_VECS) || defined (HAVE_rs6000_xcoff64_aix_vec)

{ "powerpc64-*-aix[5-9]*",
&rs6000_xcoff64_aix_vec },
#endif



    
#endif

#if !defined (SELECT_VECS) || defined (HAVE_rs6000_xcoff_vec)

{ "powerpc-*-aix*", NULL },{ "powerpc-*-beos*", NULL },{ "rs6000-*-*",
&rs6000_xcoff_vec },
#endif


    
#ifdef BFD64
#if !defined (SELECT_VECS) || defined (HAVE_rs6000_xcoff64_vec)

{ "powerpc64-*-aix*",
&rs6000_xcoff64_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_powerpc_elf64_fbsd_vec)

{ "powerpc64-*-freebsd*",
&powerpc_elf64_fbsd_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_powerpc_elf64_fbsd_le_vec)

{ "powerpc64le-*-freebsd*",
&powerpc_elf64_fbsd_le_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_powerpc_elf64_vec)

{ "powerpc64-*-elf*", NULL },{ "powerpc-*-elf64*", NULL },{ "powerpc64-*-linux*", NULL },
{ "powerpc64-*-*bsd*",
&powerpc_elf64_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_powerpc_elf64_le_vec)

{ "powerpc64le-*-elf*", NULL },{ "powerpcle-*-elf64*", NULL },{ "powerpc64le-*-linux*", NULL },
{ "powerpc64le-*-*bsd*",
&powerpc_elf64_le_vec },
#endif



    
#endif
#if !defined (SELECT_VECS) || defined (HAVE_powerpc_elf32_fbsd_vec)

{ "powerpc-*-*freebsd*",
&powerpc_elf32_fbsd_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_powerpc_elf32_vec)

{ "powerpc-*-*bsd*", NULL },{ "powerpc-*-elf*", NULL },{ "powerpc-*-sysv4*", NULL },{ "powerpc-*-eabi*", NULL },
{ "powerpc-*-linux-*", NULL },{ "powerpc-*-rtems*", NULL },{ "powerpc-*-chorus*",
&powerpc_elf32_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_powerpc_elf32_vec)

{ "powerpc-*-haiku*",
&powerpc_elf32_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_powerpc_elf32_vec)

{ "powerpc-*-kaos*",
&powerpc_elf32_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_mach_o_be_vec)

{ "powerpc-*-darwin*", NULL },{ "powerpc-*-macos10*", NULL },{ "powerpc-*-rhapsody*",
&mach_o_be_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_powerpc_xcoff_vec)

{ "powerpc-*-macos*",
&powerpc_xcoff_vec },
#endif

    
#if !defined (SELECT_VECS) || defined (HAVE_powerpc_elf32_vec)

{ "powerpc-*-nto*",
&powerpc_elf32_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_powerpc_elf32_vxworks_vec)

{ "powerpc-*-vxworks*",
&powerpc_elf32_vxworks_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_powerpc_elf32_le_vec)

{ "powerpcle-*-nto*",
&powerpc_elf32_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_powerpc_elf32_le_vec)

{ "powerpcle-*-elf*", NULL },{ "powerpcle-*-sysv4*", NULL },{ "powerpcle-*-eabi*", NULL },
{ "powerpcle-*-linux-*", NULL },{ "powerpcle-*-vxworks*",
&powerpc_elf32_le_vec },
#endif



    

#if !defined (SELECT_VECS) || defined (HAVE_pru_elf32_vec)

{ "pru-*-*",
&pru_elf32_vec },
#endif

    

#ifdef BFD64
#if !defined (SELECT_VECS) || defined (HAVE_riscv_elf32_be_vec)

{ "riscvbe-*-*", NULL },{ "riscv32be*-*-*",
&riscv_elf32_be_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_riscv_elf32_vec)

{ "riscv-*-*", NULL },{ "riscv32*-*-*",
&riscv_elf32_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_riscv_elf64_be_vec)

{ "riscv64be*-*-*",
&riscv_elf64_be_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_riscv_elf64_vec)

{ "riscv64*-*-*",
&riscv_elf64_vec },
#endif



    
#endif

#if !defined (SELECT_VECS) || defined (HAVE_rl78_elf32_vec)

{ "rl78-*-elf",
&rl78_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_rx_elf32_le_vec)

{ "rx-*-elf",
&rx_elf32_le_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_rx_elf32_linux_le_vec)

{ "rx-*-linux*",
&rx_elf32_linux_le_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_s390_elf32_vec)

{ "s390-*-linux*",
&s390_elf32_vec },
#endif



    
#ifdef BFD64
#if !defined (SELECT_VECS) || defined (HAVE_s390_elf64_vec)

{ "s390x-*-linux*",
&s390_elf64_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_s390_elf64_vec)

{ "s390x-*-tpf*",
&s390_elf64_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_score_elf32_be_vec)

{ "score*-*-elf*",
&score_elf32_be_vec },
#endif


    
#endif /* BFD64 */

#if !defined (SELECT_VECS) || defined (HAVE_sh_elf32_linux_be_vec)

{ "sh*eb-*-linux*",
&sh_elf32_linux_be_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_sh_elf32_linux_vec)

{ "sh*-*-linux*",
&sh_elf32_linux_vec },
#endif



    

#if !defined (SELECT_VECS) || defined (HAVE_sh_elf32_vec)

{ "sh-*-uclinux*", NULL },{ "sh[12]-*-uclinux*",
&sh_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_sh_elf32_nbsd_le_vec)

{ "sh*l*-*-netbsd*",
&sh_elf32_nbsd_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_sh_elf32_nbsd_vec)

{ "sh*-*-netbsd*",
&sh_elf32_nbsd_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_sh_elf32_le_vec)

{ "shl*-*-elf*", NULL },{ "sh[1234]l*-*-elf*", NULL },{ "sh3el*-*-elf*", NULL },{ "shl*-*-kaos*",
&sh_elf32_le_vec },
#endif



    

#if !defined (SELECT_VECS) || defined (HAVE_sh_elf32_vec)

{ "sh-*-elf*", NULL },{ "sh[1234]*-elf*", NULL },{ "sh-*-rtems*", NULL },{ "sh-*-kaos*",
&sh_elf32_vec },
#endif



    

#if !defined (SELECT_VECS) || defined (HAVE_sh_elf32_vec)

{ "sh-*-nto*",
&sh_elf32_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_sh_elf32_nbsd_le_vec)

{ "sh*-*-openbsd*",
&sh_elf32_nbsd_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_sh_pe_le_vec)

{ "sh-*-pe",
&sh_pe_le_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_sh_elf32_vxworks_vec)

{ "sh-*-vxworks",
&sh_elf32_vxworks_vec },
#endif







    
#if !defined (SELECT_VECS) || defined (HAVE_sh_coff_vec)

{ "sh-*-*",
&sh_coff_vec },
#endif



    


#if !defined (SELECT_VECS) || defined (HAVE_sparc_elf32_sol2_vec)

{ "sparc-*-solaris2.[0-6]", NULL },{ "sparc-*-solaris2.[0-6].*",
&sparc_elf32_sol2_vec },
#endif

    
#ifdef BFD64

#if !defined (SELECT_VECS) || defined (HAVE_sparc_elf32_sol2_vec)

{ "sparc-*-solaris2*", NULL },{ "sparcv9-*-solaris2*", NULL },{ "sparc64-*-solaris2*",
&sparc_elf32_sol2_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_sparc_elf64_vec)

{ "sparc64-*-haiku*",
&sparc_elf64_vec },
#endif



    
#if !defined (SELECT_VECS) || defined (HAVE_sparc_elf64_fbsd_vec)

{ "sparc64-*-freebsd*", NULL },{ "sparc64-*-kfreebsd*-gnu",
&sparc_elf64_fbsd_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_sparc_elf64_vec)

{ "sparc64*-*-*",
&sparc_elf64_vec },
#endif



    
#endif
#if !defined (SELECT_VECS) || defined (HAVE_sparc_elf32_vec)

{ "sparc-*-linux-*", NULL },{ "sparcv*-*-linux-*",
&sparc_elf32_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_sparc_elf32_vxworks_vec)

{ "sparc-*-vxworks*",
&sparc_elf32_vxworks_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_sparc_elf32_vec)

{ "sparc*-*-*",
&sparc_elf32_vec },
#endif

    

#if !defined (SELECT_VECS) || defined (HAVE_spu_elf32_vec)

{ "spu-*-elf",
&spu_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_tic6x_elf32_c6000_le_vec)

{ "tic6x-*-elf",
&tic6x_elf32_c6000_le_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_tic6x_elf32_linux_le_vec)

{ "tic6x-*-uclinux",
&tic6x_elf32_linux_le_vec },
#endif


    

#ifdef BFD64
#if !defined (SELECT_VECS) || defined (HAVE_tilegx_elf64_le_vec)

{ "tilegx-*-*",
&tilegx_elf64_le_vec },
#endif


    
#if !defined (SELECT_VECS) || defined (HAVE_tilegx_elf64_be_vec)

{ "tilegxbe-*-*",
&tilegx_elf64_be_vec },
#endif


    
#endif

#if !defined (SELECT_VECS) || defined (HAVE_tilepro_elf32_vec)

{ "tilepro-*-*",
&tilepro_elf32_vec },
#endif

    

#if !defined (SELECT_VECS) || defined (HAVE_ft32_elf32_vec)

{ "ft32*-*-*",
&ft32_elf32_vec },
#endif

    

#if !defined (SELECT_VECS) || defined (HAVE_v850_elf32_vec)

{ "v850*-*-*",
&v850_elf32_vec },
#endif



    

#if !defined (SELECT_VECS) || defined (HAVE_vax_aout_nbsd_vec)

{ "vax-*-netbsdaout*",
&vax_aout_nbsd_vec },
#endif



    

#if !defined (SELECT_VECS) || defined (HAVE_vax_elf32_vec)

{ "vax-*-netbsd*",
&vax_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_vax_aout_nbsd_vec)

{ "vax-*-openbsd*",
&vax_aout_nbsd_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_vax_elf32_vec)

{ "vax-*-linux-*",
&vax_elf32_vec },
#endif

    

#if !defined (SELECT_VECS) || defined (HAVE_visium_elf32_vec)

{ "visium-*-elf",
&visium_elf32_vec },
#endif

    

#if !defined (SELECT_VECS) || defined (HAVE_wasm32_elf32_vec)

{ "wasm32-*-*",
&wasm32_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_xgate_elf32_vec)

{ "xgate-*-*",
&xgate_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_xstormy16_elf32_vec)

{ "xstormy16-*-elf",
&xstormy16_elf32_vec },
#endif

    

#if !defined (SELECT_VECS) || defined (HAVE_xtensa_elf32_le_vec)

{ "xtensa*-*-*",
&xtensa_elf32_le_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_z80_coff_vec)

{ "z80-*-coff",
&z80_coff_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_z80_elf32_vec)

{ "z80-*-elf",
&z80_elf32_vec },
#endif


    

#if !defined (SELECT_VECS) || defined (HAVE_z8k_coff_vec)

{ "z8k*-*-*",
&z8k_coff_vec },
#endif


    

#ifdef BFD64
#if !defined (SELECT_VECS) || defined (HAVE_loongarch_elf32_vec)

{ "loongarch32-*",
&loongarch_elf32_vec },
#endif



    

#if !defined (SELECT_VECS) || defined (HAVE_loongarch_elf64_vec)

{ "loongarch64-*",
&loongarch_elf64_vec },
#endif



    
#endif

