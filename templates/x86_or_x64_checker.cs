using System;

namespace a
{
    class b
    {
        public static int Main()
        {
            if (IntPtr.Size == 4)
            {
                Console.Write("[*] process running in 32bit");
                // some 32bit dependant condition
            }
            else if (IntPtr.Size == 8)
            {
                Console.Write("[*] process running in 64bit");
                // some 64bit dependant condition
            }
            return 0;
        }
        }
    }
