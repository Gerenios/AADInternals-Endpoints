# Native Windows functions

$source=@"
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections;
using System.Collections.Generic;
using System.Management.Automation;

namespace AADInternals
{

    public static class Native
    {
        /**
        * Type definitions
        */
        private enum DhcpRequestFlags : uint
        {
            DHCPCAPI_REQUEST_PERSISTENT = 1U,
            DHCPCAPI_REQUEST_SYNCHRONOUS = 2U,
            DHCPCAPI_REQUEST_ASYNCHRONOUS = 4U,
            DHCPCAPI_REQUEST_CANCEL = 8U,
            DHCPCAPI_REQUEST_MASK = 15U
        }

        private struct DHCPCAPI_PARAMS_ARRAY
        {
            public uint nParams;
            public IntPtr Params;
        }

        private struct DHCPCAPI_PARAMS
        {
            public uint Flags;
            public uint OptionId;
            [MarshalAs(UnmanagedType.Bool)]
            public bool IsVendor;
            public IntPtr Data;
            public uint nBytesData;
        }


        /**
        * Native methods
        */

        [DllImport("dhcpcsvc.dll", CharSet = CharSet.Unicode)]
        private static extern int DhcpRequestParams(DhcpRequestFlags Flags, IntPtr Reserved, string AdapterName, IntPtr ClassId, DHCPCAPI_PARAMS_ARRAY SendParams, DHCPCAPI_PARAMS_ARRAY RecdParams, IntPtr Buffer, ref uint pSize, string RequestIdStr);

        [DllImport("dhcpcsvc.dll", CharSet = CharSet.Unicode)]
        private static extern int DhcpUndoRequestParams(uint Flags, IntPtr Reserved, string AdapterName, string RequestIdStr);

        [DllImport("dhcpcsvc.dll", CharSet = CharSet.Unicode)]
        private static extern int DhcpCApiInitialize(out uint Version);

        [DllImport("dhcpcsvc.dll", CharSet = CharSet.Unicode)]
        private static extern int DhcpCApiCleanup();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Int32 RegQueryInfoKey(
            Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey,
            StringBuilder lpClass,
            [In, Out] ref UInt32 lpcbClass,
            UInt32 lpReserved,
            out UInt32 lpcSubKeys,
            out UInt32 lpcbMaxSubKeyLen,
            out UInt32 lpcbMaxClassLen,
            out UInt32 lpcValues,
            out UInt32 lpcbMaxValueNameLen,
            out UInt32 lpcbMaxValueLen,
            out UInt32 lpcbSecurityDescriptor,
            out Int64 lpftLastWriteTime
        );

        /**
         * Ncrypt imports
         */
        [DllImport("ncrypt.dll", SetLastError = true)]
        private static extern int NCryptOpenStorageProvider(
            ref IntPtr hProvider,
            [MarshalAs(UnmanagedType.LPWStr)] string szProviderName,
            int dwFlags);

        [DllImport("ncrypt.dll", SetLastError = true)]
        private static extern int NCryptImportKey(
            IntPtr hProvider,
            IntPtr hImportKey,
            [MarshalAs(UnmanagedType.LPWStr)] string szBlobType,
            IntPtr pParameterList, //shoud be NcryptBufferDesc
            ref IntPtr phKey,
            byte[] pbData,
            int cbData,
            int dwFlags);

        [DllImport("ncrypt.dll", SetLastError = true)]
        private static extern int NCryptExportKey(
            IntPtr hKey,
            IntPtr hExportKey,
            [MarshalAs(UnmanagedType.LPWStr)] string szBlobType,
            IntPtr pParameterList, //shoud be NcryptBufferDesc 
            [In, Out] byte[] pbOutput,
            uint cbOutput,
            ref uint pcbResult,
            int dwFlags);

        [DllImport("ncrypt.dll", SetLastError = true)]
        private static extern int NCryptSetProperty(
            IntPtr hKey,
            [MarshalAs(UnmanagedType.LPWStr)] string szProperty,
            byte[] pbInput,
            int cbInput,
            int dwFlags);

        [DllImport("ncrypt.dll", SetLastError = true)]
        private static extern int NCryptFinalizeKey(
            IntPtr hKey,
            int dwFlags);

        [DllImport("ncrypt.dll", SetLastError = true)]
        private static extern int NCryptFreeObject(
            IntPtr hObject);

        [DllImport("Ncrypt.dll", SetLastError = true)]
        private static extern int NCryptDecrypt(
                IntPtr hKey,
                [MarshalAs(UnmanagedType.LPArray)] byte[] pbInput,
                int cbInput,
                IntPtr pPaddingInfo,
                [MarshalAs(UnmanagedType.LPArray)] byte[] pbOutput,
                int cbOutput,
                ref int pcbResult,
                int dwFlags);

        /**
         * BCRYPT.dll imports
        */

        [DllImport("bcrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint BCryptOpenAlgorithmProvider(
            out IntPtr phAlgorithm,
            string pszAlgId,
            string pszImplementation,
            uint dwFlags);

        [DllImport("bcrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint BCryptCreateHash(
            IntPtr phAlgorithm,
            out IntPtr phHash,
            byte[] pbHashObject,
            //out IntPtr pbHashObject ,
            uint cbHashObject,
            byte[] pbSecret,
            uint cbSecret,
            uint dwFlags);

        [DllImport("bcrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint BCryptHashData(
            IntPtr hHash,
            byte[] pbInput,
            uint cbInput,
            uint dwFlags);

        [DllImport("bcrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint BCryptFinishHash(
            IntPtr hHash,
            byte[] pbOutput,
            uint cbOutput,
            uint dwFlags);

        [DllImport("bcrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint BCryptGetProperty(
            IntPtr hObject,
            string pszProperty,
            out IntPtr pbOutput,
            uint cbOutput,
            out uint pcbResult,
            uint dwFlags);

        [DllImport("bcrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint BCryptCloseAlgorithmProvider(
            IntPtr hAlgorithm,
            uint dwFlags);

        [DllImport("bcrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint BCryptDestroyHash(
            IntPtr hHash);

        [DllImport("bcrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint BCryptDeriveKeyPBKDF2(
            IntPtr hAlgorighm,
            byte[] pbPassword,
            uint cbPassword,
            byte[] pbSalt,
            uint cbSalt,
            UInt64 cIterations,
            byte[] pbDerivedKey,
            uint cbDerviedKey,
            uint dwFlags);

        /**
         * Utility function to calculate SHA256 from the given data using HMAC flag. Don't ask..
         */
        public static byte[] getSHA256withHMACFlag(byte[] data)
        {
            IntPtr phAlgorithm = IntPtr.Zero;
            IntPtr phHash = IntPtr.Zero;
            byte[] retVal = null;
            byte[] hash = new byte[0x20];
            uint status;
            // BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008
            if ((status = BCryptOpenAlgorithmProvider(out phAlgorithm, "SHA256", null, 8)) == 0)
            {
                if ((status = BCryptCreateHash(phAlgorithm, out phHash, null, 0, null, 0, 0)) == 0)
                {
                    if ((status = BCryptHashData(phHash, data, (uint)data.Length, 0)) == 0)
                    {
                        if ((status = BCryptFinishHash(phHash, hash, 0x20, 0)) == 0)
                        {
                            retVal = hash;
                        }
                    }
                    BCryptDestroyHash(phHash);
                }
                BCryptCloseAlgorithmProvider(phAlgorithm, 0);
            }
            return retVal;
        }

        /**
         * Utility function for converting keys to different formats
         */
                
        public static byte[] convertKey(byte[] key, string sourceType = "RSAPRIVATEBLOB", string targetType = "CAPIPRIVATEBLOB")
        {
            IntPtr hProv = new IntPtr();
            IntPtr hKey = new IntPtr();

            byte[] retVal = null;
            int status = 0;
            if((status = NCryptOpenStorageProvider(ref hProv, "Microsoft Software Key Storage Provider",0)) == 0)
            {
                if((status = NCryptImportKey(hProv, IntPtr.Zero, sourceType, IntPtr.Zero, ref hKey, key,key.Length, 0x00000400  /*NCRYPT_DO_NOT_FINALIZE_FLAG*/)) == 0)
                {
                    // Export policy:
                    // NCRYPT_ALLOW_EXPORT_FLAG           = 0x00000001
                    // NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG = 0x00000002
                    byte[] policy = { 0x03, 0x00, 0x00, 0x00 };
                    if ((status = NCryptSetProperty(hKey,"Export Policy",policy,4,0)) == 0)
                    {
                        if ((status = NCryptFinalizeKey(hKey,0)) == 0) 
                        {
                            uint blobSize = 0;

                            if ((status = NCryptExportKey(hKey, IntPtr.Zero, targetType, IntPtr.Zero, null, blobSize, ref blobSize, 0)) == 0)
                            {
                                byte[] blob = new byte[blobSize];
                                if ((status = NCryptExportKey(hKey, IntPtr.Zero, targetType, IntPtr.Zero, blob, blobSize, ref blobSize, 0)) == 0)
                                {
                                    retVal = blob;
                                }
                            }

                        }
                    }
                    NCryptFreeObject(hKey);
                }
                NCryptFreeObject(hProv);
            }
            if (status != 0)
            {
                //Console.WriteLine(string.Format("Error: 0x{0}", status.ToString("x8")));
                throw new ExternalException( string.Format("Error: 0x{0}", status.ToString("x8")),status);
            }

            return retVal;
        }

        /**
         * Utility function for calling ProofOfPossessionCookieInfoManager COM method based on work by Lee Christensen
         * https://github.com/leechristensen/RequestAADRefreshToken
         */

        [Guid("CDAECE56-4EDF-43DF-B113-88E4556FA1BB")]
        [ComImport]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IProofOfPossessionCookieInfoManager
        {
            int GetCookieInfoForUri(
                [MarshalAs(UnmanagedType.LPWStr)] string Uri,
                out uint cookieInfoCount,
                out IntPtr output
            );
        }

        [Guid("A9927F85-A304-4390-8B23-A75F1C668600")]
        [ComImport]
        private class WindowsTokenProvider
        {
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UnsafeProofOfPossessionCookieInfo
        {
            public readonly IntPtr NameStr;
            public readonly IntPtr DataStr;
            public readonly uint Flags;
            public readonly IntPtr P3PHeaderStr;
        }


        public static List<PSObject> getCookieInfoForUri(string uri)
        {
            var provider = (IProofOfPossessionCookieInfoManager)new WindowsTokenProvider();
            uint count = 0;
            var ptr = IntPtr.Zero;
            provider.GetCookieInfoForUri(uri, out count, out ptr);

            List<PSObject> retVal = new List<PSObject>();

            var offset = ptr;
            for (int i = 0; i < count; i++)
            {
                var info = (UnsafeProofOfPossessionCookieInfo)Marshal.PtrToStructure(offset, typeof(UnsafeProofOfPossessionCookieInfo));

                Hashtable properties = new Hashtable();
                properties.Add("name", Marshal.PtrToStringUni(info.NameStr));
                properties.Add("data", Marshal.PtrToStringUni(info.DataStr));
                properties.Add("flags", info.Flags);
                properties.Add("p3pheader", Marshal.PtrToStringUni(info.P3PHeaderStr));

                retVal.Add(new PSObject(properties));

                Marshal.FreeCoTaskMem(info.NameStr);
                Marshal.FreeCoTaskMem(info.DataStr);
                Marshal.FreeCoTaskMem(info.P3PHeaderStr);

                offset = (IntPtr)(offset.ToInt64() + Marshal.SizeOf(typeof(UnsafeProofOfPossessionCookieInfo)));
            }

            Marshal.FreeCoTaskMem(ptr);

            return retVal;
        }

        /**
         * Utility function for getting Wire Server ip address for WindowsAzureGuestAgent using DHCP
         */
        public static System.Net.IPAddress getWireServerIpAddress(string adapterName, uint optionId = 245U)
        {
            uint num = 1024U;
            System.Net.IPAddress result = null;
            for (; ; )
            {
                IntPtr intPtr = Marshal.AllocHGlobal((int)num);
                try
                {
                    DHCPCAPI_PARAMS_ARRAY sendParams = default(DHCPCAPI_PARAMS_ARRAY);
                    sendParams.nParams = 0U;
                    sendParams.Params = IntPtr.Zero;
                    DHCPCAPI_PARAMS dhcpcapi_PARAMS = new DHCPCAPI_PARAMS
                    {
                        Flags = 0U,
                        OptionId = optionId,
                        IsVendor = false,
                        Data = IntPtr.Zero,
                        nBytesData = 0U
                    };
                    IntPtr intPtr2 = Marshal.AllocHGlobal(Marshal.SizeOf(dhcpcapi_PARAMS));
                    try
                    {
                        Marshal.StructureToPtr(dhcpcapi_PARAMS, intPtr2, false);
                        DHCPCAPI_PARAMS_ARRAY recdParams = default(DHCPCAPI_PARAMS_ARRAY);
                        recdParams.nParams = 1U;
                        recdParams.Params = intPtr2;
                        int retVal = DhcpRequestParams(DhcpRequestFlags.DHCPCAPI_REQUEST_SYNCHRONOUS, IntPtr.Zero, adapterName, IntPtr.Zero, sendParams, recdParams, intPtr, ref num, "WindowsAzureGuestAgent");
                        if ((long)retVal == 124L)
                        {
                            num *= 2U;
                            continue;
                        }
                        if (retVal==0)
                        {
                            dhcpcapi_PARAMS = (DHCPCAPI_PARAMS)Marshal.PtrToStructure(intPtr2, typeof(DHCPCAPI_PARAMS));
                            if (dhcpcapi_PARAMS.Data != IntPtr.Zero)
                            {
                                byte[] array = new byte[dhcpcapi_PARAMS.nBytesData];
                                Marshal.Copy(dhcpcapi_PARAMS.Data, array, 0, (int)dhcpcapi_PARAMS.nBytesData);
                                if (array.Length == 4)
                                {
                                    result = new System.Net.IPAddress(array);
                                }
                            }
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(intPtr2);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(intPtr);
                }
                break;
            }
            // Clean up
            DhcpCApiCleanup();
            return result;
        }

        /**
        * Utility functions for getting PRT using LSAS CloudAP based on work of Yuya Chudo from Secureworks
        * https://github.com/secureworks/BAADTokenBroker/blob/main/BAADTokenBroker.ps1
        */
        
        const string pbLabel = "AzureAD-SecureConversation";
        const int STARTF_USESHOWWINDOW = 0x00000001;
        const int SW_HIDE = 0x00000000;
        const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        const int PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009;
        const uint TOKEN_DUPLICATE = 0x0002;
        const int SecurityImpersonation = 2;

        private static IntPtr hImpProc = IntPtr.Zero;
        private static IntPtr hImpToken = IntPtr.Zero;
        private static IntPtr hImpDupToken = IntPtr.Zero;

        private const int STATUS_SUCCESS = 0;
        private const int CALLPKG_GENERIC = 2;
        private static readonly Guid AadGlobalIdProviderGuid = new Guid(
            0xB16898C6, 0xA148, 0x4967, 0x91, 0x71, 0x64, 0xD7, 0x55, 0xDA, 0x85, 0x20
        );

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_CAPABILITIES
        {
            public IntPtr AppContainerSid;
            public IntPtr Capabilities;
            public uint CapabilityCount;
            public uint Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CAP_PKG_INPUT
        {
            public uint ulMessageType;
            public Guid ProviderGuid;
            public uint ulInputSize;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public byte[] abInput;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct NGC_IDP_ACCOUNT_INFO
        {
            public string idpDomain;
            public string tenantid;
            public IntPtr val3;
        };

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct NGC_KEY_INFO
        {
            public IntPtr idpDomain;
            public string tenantid;
            public IntPtr userId;
            public IntPtr sid;
            public IntPtr keyName;
        };

        [DllImport("kernel32.dll")]
        private static extern bool CreateProcess(
            string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, ref SECURITY_CAPABILITIES securityCapabilities,
            IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("KERNEL32.dll", SetLastError = true)]
        private static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ConvertStringSidToSid(string StringSid, out IntPtr ptrSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll")]
        private extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, ref IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int LsaConnectUntrusted(out IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int LsaLookupAuthenticationPackage(IntPtr LsaHandle, ref LSA_STRING PackageName, out uint AuthenticationPackage);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int LsaCallAuthenticationPackage(IntPtr LsaHandle, uint AuthenticationPackage, IntPtr ProtocolSubmitBuffer, int SubmitBufferLength, out IntPtr ProtocolReturnBuffer, out int ReturnBufferLength, out int ProtocolStatus);

        [DllImport("SECUR32.dll", SetLastError = true)]
        private static extern int LsaFreeReturnBuffer(IntPtr Buffer);

        [DllImport("kernel32.dll")]
        private static extern void RtlZeroMemory(IntPtr dst, UIntPtr length);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool RevertToSelf();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("cryptngc.dll")]
        private static extern int NgcImportSymmetricPopKey(ref NGC_IDP_ACCOUNT_INFO accountInfo, IntPtr arg2, IntPtr arg3, IntPtr sessionKey, uint cbSessionKey, out IntPtr pbKey, out uint cbKey);

        [DllImport("cryptngc.dll")]
        private static extern int NgcSignWithSymmetricPopKey(IntPtr pbKey, uint cbKey, string pbLabel, uint cbLabel, IntPtr pbContext, uint cbContext, string pbData, uint cbData, out IntPtr ppbOutput, out uint pcbOutput);

        [DllImport("cryptngc.dll")]
        private static extern int NgcDecryptWithSymmetricPopKey(IntPtr pbKey, uint cbKey, string pbLabel, uint cbLabel, IntPtr pbContext, uint cbContext, IntPtr pbIv, uint cbIv, IntPtr pbData, uint cbData, out IntPtr ppbOutput, out uint pcbOutput);

        [DllImport("cryptngc.dll")]
        private static extern int NgcEncryptWithSymmetricPopKey(IntPtr pbKey, uint cbKey, string pbLabel, uint cbLabel, IntPtr pbContext, uint cbContext, IntPtr pbIv, uint cbIv, string pbData, uint cbData, out IntPtr ppbOutput, out uint pcbOutput);

        [DllImport("cryptngc.dll")]
        private static extern int NgcGetUserIdKeyPublicKey(byte[] keyName, out IntPtr ppbOutput, out uint pcbOutput);

        [DllImport("cryptngc.dll")]
        private static extern int NgcSignWithUserIdKey(byte[] keyName, string pbData, uint cbData, uint Val, out IntPtr ppbOutput, out uint pcbOutput);

        [DllImport("cryptngc.dll", CharSet = CharSet.Unicode)]
        private static extern int NgcEnumUserIdKeys(string idpDomain, string tenantDomain, string userId, string userSid, out IntPtr pbOutput, out uint pcbOutput);

        private static bool Impersonate()
        {
            bool success = false;
            IntPtr appContainerSid;
            if (ConvertStringSidToSid("S-1-15-2-1910091885-1573563583-1104941280-2418270861-3411158377-2822700936-2990310272", out appContainerSid))
            {
                var sInfoEx = new STARTUPINFOEX();
                sInfoEx.StartupInfo = new STARTUPINFO();
                sInfoEx.StartupInfo.cb = Marshal.SizeOf(sInfoEx);
                sInfoEx.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
                sInfoEx.StartupInfo.wShowWindow = SW_HIDE;

                var lpSize = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
                sInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);

                if (InitializeProcThreadAttributeList(sInfoEx.lpAttributeList, 1, 0, ref lpSize))
                {
                    var securityCapablities = new SECURITY_CAPABILITIES();
                    securityCapablities.AppContainerSid = appContainerSid;

                    if (UpdateProcThreadAttribute(
                        sInfoEx.lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                        ref securityCapablities, (IntPtr)Marshal.SizeOf(securityCapablities), IntPtr.Zero, IntPtr.Zero))
                    {
                        var pInfo = new PROCESS_INFORMATION();
                        var pSec = new SECURITY_ATTRIBUTES();
                        var tSec = new SECURITY_ATTRIBUTES();
                        pSec.nLength = Marshal.SizeOf(pSec);
                        tSec.nLength = Marshal.SizeOf(tSec);

                        if (CreateProcess("C:\\Windows\\system32\\Notepad.exe", "", ref pSec, ref tSec,
                            false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, "C:\\", ref sInfoEx, out pInfo))
                        {
                            hImpProc = pInfo.hProcess;
                            if (OpenProcessToken(hImpProc, TOKEN_DUPLICATE, out hImpToken))
                            {
                                if (DuplicateToken(hImpToken, SecurityImpersonation, ref hImpDupToken))
                                {
                                    success = ImpersonateLoggedOnUser(hImpDupToken);
                                }
                            }
                        }
                    }
                    DeleteProcThreadAttributeList(sInfoEx.lpAttributeList);
                    Marshal.FreeHGlobal(sInfoEx.lpAttributeList);
                }
            }
            Console.WriteLine("ImpersonateLoggedOnUser: {0}",success);
            return success;
        }

        private static void Revert()
        {
            RevertToSelf();

            if (hImpDupToken != IntPtr.Zero)
            {
                CloseHandle(hImpDupToken);
            }

            if (hImpToken != IntPtr.Zero)
            {
                CloseHandle(hImpToken);
            }

            if (hImpProc != IntPtr.Zero)
            {
                TerminateProcess(hImpProc, 0);
            }
            return;
        }

        private static IntPtr GetLsaHandle()
        {
            IntPtr hLsa;
            int status = LsaConnectUntrusted(out hLsa);
            if (status != STATUS_SUCCESS)
            {
                return IntPtr.Zero;
            }
            return hLsa;
        }

        private static uint GetCloudApPackageId(IntPtr hLsa)
        {
            string szCloudAPName = "CloudAP";
            LSA_STRING cloudApPackageName = new LSA_STRING
            {
                Length = (ushort)(szCloudAPName.Length),
                MaximumLength = (ushort)((szCloudAPName.Length + 1)),
                Buffer = Marshal.StringToHGlobalAnsi(szCloudAPName)
            };

            uint cloudApPackageId;
            int status = LsaLookupAuthenticationPackage(hLsa, ref cloudApPackageName, out cloudApPackageId);
            Marshal.FreeHGlobal(cloudApPackageName.Buffer);
            if (status != STATUS_SUCCESS)
            {
                string strError = status.ToString("x");
                Console.WriteLine("GetCloudApPackageId Error: 0x{0}", strError);
                return 0;
            }
            return cloudApPackageId;
        }

        private static string CallCloudAP(IntPtr hLsa, uint cloudApPackageId, string payload)
        {
            CAP_PKG_INPUT capPkgInput = new CAP_PKG_INPUT();
            capPkgInput.ulMessageType = CALLPKG_GENERIC;
            capPkgInput.ProviderGuid = AadGlobalIdProviderGuid;
            capPkgInput.ulInputSize = (uint)payload.Length;

            IntPtr capPkgInputPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CAP_PKG_INPUT)));
            Marshal.StructureToPtr(capPkgInput, capPkgInputPtr, false);

            byte[] capPkgInputBytes = new byte[Marshal.SizeOf(typeof(CAP_PKG_INPUT))];
            Marshal.Copy(capPkgInputPtr, capPkgInputBytes, 0, Marshal.SizeOf(typeof(CAP_PKG_INPUT)));
            Marshal.FreeHGlobal(capPkgInputPtr);

            int cbCloudApRequest = Marshal.SizeOf(typeof(CAP_PKG_INPUT)) + 1 + payload.Length;
            IntPtr cloudApRequestBuf = Marshal.AllocHGlobal(cbCloudApRequest);
            RtlZeroMemory(cloudApRequestBuf, (UIntPtr)cbCloudApRequest);
            Marshal.Copy(capPkgInputBytes, 0, cloudApRequestBuf, Marshal.SizeOf(typeof(CAP_PKG_INPUT)));

            byte[] requestJsonBuffer = System.Text.Encoding.ASCII.GetBytes(payload);
            Marshal.Copy(requestJsonBuffer, 0, cloudApRequestBuf + 4 + 16 + 4, payload.Length);

            int cbCloudApResponse;
            IntPtr pResponseBuffer;
            int subStatus;
            int status = LsaCallAuthenticationPackage(
                hLsa,
                cloudApPackageId,
                cloudApRequestBuf,
                cbCloudApRequest,
                out pResponseBuffer,
                out cbCloudApResponse,
                out subStatus
            );
            Marshal.FreeHGlobal(cloudApRequestBuf);

            string response = "";
            if (status == STATUS_SUCCESS)
            {
                if (pResponseBuffer != IntPtr.Zero)
                {
                    byte[] cloudApResponseBytes = new byte[cbCloudApResponse];
                    Marshal.Copy(pResponseBuffer, cloudApResponseBytes, 0, cbCloudApResponse);
                    LsaFreeReturnBuffer(pResponseBuffer);
                    response = Encoding.UTF8.GetString(cloudApResponseBytes, 0, cloudApResponseBytes.Length);
                }
            }
            else
            {
                string strError = status.ToString("x");
                Console.WriteLine("Error: 0x{0}", strError);
                Console.WriteLine("Payload: {0}", payload);
            }

            return response;
        }
        private static string SendToCloudAp(string payload)
        {
            string response = "";
            IntPtr hLsa = GetLsaHandle();
            if (hLsa != IntPtr.Zero)
            {
                uint cloudApPackageId = GetCloudApPackageId(hLsa);
                if (cloudApPackageId != 0 && Impersonate())
                {
                    response = CallCloudAP(hLsa, cloudApPackageId, payload);
                    Revert();
                }
            }
            return response;
        }

        public static string RequestSSOCookie(string nonce)
        {
            string payload = string.Format("{{\"call\": 2, \"payload\":\"https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce={0}\", \"correlationId\":\"00000000-0000-0000-0000-000000000000\"}}", nonce);
            return SendToCloudAp(payload);
        }

    }
}
"@
Add-Type -TypeDefinition $source -Language CSharp  -Verbose
