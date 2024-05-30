
import signal

import gdb
import pwndbg.gdblib
import pwndbg.dbg

import pwndbg.commands
from pwndbg.commands import load_commands

from pwndbg.gdblib import gdb_version
from pwndbg.gdblib import prompt
from pwndbg.gdblib import load_gdblib

class GDB(pwndbg.dbg.Debugger):
    def setup(self):
        load_gdblib()
        load_commands()

        prompt.set_prompt()                                                                
                                                                                   
        pre_commands = f"""                                                                
        set confirm off                                                                    
        set verbose off                                                                    
        set pagination off                                                                 
        set height 0                                                                       
        set history save on                                                                
        set follow-fork-mode child                                                         
        set backtrace past-main on                                                         
        set step-mode on                                                                   
        set print pretty on                                                                
        set width {pwndbg.ui.get_window_size()[1]}                                         
        handle SIGALRM nostop print nopass                                                 
        handle SIGBUS  stop   print nopass                                                 
        handle SIGPIPE nostop print nopass                                                 
        handle SIGSEGV stop   print nopass                                                 
        """.strip()                                                                        
                                                                                           
        # See https://github.com/pwndbg/pwndbg/issues/808                                  
        if gdb_version[0] <= 9:                                                            
            pre_commands += "\nset remote search-memory-packet off"                        
                                                                                           
        for line in pre_commands.strip().splitlines():                                     
            gdb.execute(line)                                                              
                                                                                           
        # This may throw an exception, see pwndbg/pwndbg#27                                
        try:                                                                               
            gdb.execute("set disassembly-flavor intel")                                    
        except gdb.error:                                                                  
            pass                                                                           
                                                                                           
        # handle resize event to align width and completion                                
        signal.signal(                                                                     
            signal.SIGWINCH,                                                               
            lambda signum, frame: gdb.execute("set width %i" % pwndbg.ui.get_window_size()[1]),
        )                                                                                  
                                                                                           
        # Reading Comment file                                                             
        from pwndbg.commands import comments                                               
                                                                                           
        comments.init()                                                                    
                                                                                           
        from pwndbg.gdblib import config_mod                                               
                                                                                           
        config_mod.init_params()

