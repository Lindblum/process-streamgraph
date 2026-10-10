using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace ProcessStreamgraph
{
    internal enum SignatureState { Valid, Unsigned, Untrusted, Invalid }

    /// <summary>
    /// Authenticode check of a file, as Windows itself does it: a signature embedded in the file, or
    /// failing that one in the system's security catalogs, which is how most Windows files are signed.
    /// </summary>
    internal static class FileSignature
    {
        public static SignatureState Check(string path, out string signer, out string detail)
        {
            signer = null;
            detail = null;

            int result = VerifyEmbedded(path);
            if (result == 0)
            {
                signer = SignerOf(path);
                return SignatureState.Valid;
            }
            if (result == TRUST_E_NOSIGNATURE || result == TRUST_E_SUBJECT_FORM_UNKNOWN || result == TRUST_E_PROVIDER_UNKNOWN)
            {
                result = VerifyCatalog(path, out string catalog);
                if (result == 0)
                {
                    signer = catalog != null ? SignerOf(catalog) : null;
                    return SignatureState.Valid;
                }
                if (catalog == null) return SignatureState.Unsigned;
            }

            switch (result)
            {
                case TRUST_E_BAD_DIGEST:
                    detail = "The signature does not match the file's contents, so the file was changed after it was signed.";
                    return SignatureState.Invalid;
                case CERT_E_REVOKED:
                    detail = "The signing certificate has been revoked, which usually means it was stolen or misused.";
                    return SignatureState.Invalid;
                case TRUST_E_EXPLICIT_DISTRUST:
                    detail = "The signing certificate is explicitly distrusted by Windows.";
                    return SignatureState.Invalid;
                case CERT_E_EXPIRED:
                    detail = "The signing certificate has expired and the signature has no timestamp.";
                    return SignatureState.Untrusted;
                case CERT_E_UNTRUSTEDROOT:
                case CERT_E_CHAINING:
                    detail = "The signing certificate does not lead to an authority Windows trusts.";
                    return SignatureState.Untrusted;
                default:
                    detail = $"Windows could not verify the signature (error 0x{result:X8}).";
                    return SignatureState.Untrusted;
            }
        }

        private static string SignerOf(string signedFile)
        {
            try
            {
                using (var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(signedFile)))
                    return certificate.GetNameInfo(X509NameType.SimpleName, false);
            }
            catch (Exception e) when (e is System.Security.Cryptography.CryptographicException || e is IOException)
            {
                return null;
            }
        }

        private static int VerifyEmbedded(string path)
        {
            var file = new WINTRUST_FILE_INFO { cbStruct = Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = path };
            IntPtr union = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            try
            {
                Marshal.StructureToPtr(file, union, false);
                return Verify(WTD_CHOICE_FILE, union);
            }
            finally
            {
                Marshal.DestroyStructure<WINTRUST_FILE_INFO>(union);
                Marshal.FreeHGlobal(union);
            }
        }

        /// <summary>Looks the file's hash up in the system catalogs; catalog is null when it is in none of them.</summary>
        private static int VerifyCatalog(string path, out string catalog)
        {
            catalog = null;
            using (FileStream stream = OpenShared(path))
            {
                if (stream == null) return TRUST_E_NOSIGNATURE;
                // Newer catalogs list SHA-256 hashes, older ones SHA-1.
                foreach (string algorithm in new[] { "SHA256", null })
                {
                    if (!CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0)) continue;
                    try
                    {
                        int size = 0;
                        CryptCATAdminCalcHashFromFileHandle2(admin, stream.SafeFileHandle, ref size, null, 0);
                        if (size == 0) continue;
                        var hash = new byte[size];
                        if (!CryptCATAdminCalcHashFromFileHandle2(admin, stream.SafeFileHandle, ref size, hash, 0)) continue;

                        IntPtr previous = IntPtr.Zero;
                        IntPtr info = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, ref previous);
                        if (info == IntPtr.Zero) continue;
                        try
                        {
                            var catalogInfo = new CATALOG_INFO { cbStruct = Marshal.SizeOf<CATALOG_INFO>() };
                            if (!CryptCATCatalogInfoFromContext(info, ref catalogInfo, 0)) continue;
                            catalog = catalogInfo.wszCatalogFile;
                            return VerifyCatalogMember(path, catalog, hash, admin);
                        }
                        finally
                        {
                            CryptCATAdminReleaseCatalogContext(admin, info, 0);
                        }
                    }
                    finally
                    {
                        CryptCATAdminReleaseContext(admin, 0);
                    }
                }
            }
            return TRUST_E_NOSIGNATURE;
        }

        private static int VerifyCatalogMember(string path, string catalog, byte[] hash, IntPtr admin)
        {
            IntPtr hashBuffer = Marshal.AllocHGlobal(hash.Length);
            IntPtr union = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            try
            {
                Marshal.Copy(hash, 0, hashBuffer, hash.Length);
                var info = new WINTRUST_CATALOG_INFO
                {
                    cbStruct = Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                    pcwszCatalogFilePath = catalog,
                    pcwszMemberTag = BitConverter.ToString(hash).Replace("-", ""),
                    pcwszMemberFilePath = path,
                    pbCalculatedFileHash = hashBuffer,
                    cbCalculatedFileHash = hash.Length,
                    hCatAdmin = admin
                };
                Marshal.StructureToPtr(info, union, false);
                int result = Verify(WTD_CHOICE_CATALOG, union);
                Marshal.DestroyStructure<WINTRUST_CATALOG_INFO>(union);
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(union);
                Marshal.FreeHGlobal(hashBuffer);
            }
        }

        private static int Verify(int choice, IntPtr union)
        {
            var data = new WINTRUST_DATA
            {
                cbStruct = Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = choice,
                pUnion = union,
                dwStateAction = WTD_STATEACTION_VERIFY,
                // Revocation lists are not fetched; this check stays offline and quick.
                dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL
            };
            Guid action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            int result = WinVerifyTrust(INVALID_HANDLE_VALUE, ref action, ref data);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(INVALID_HANDLE_VALUE, ref action, ref data);
            return result;
        }

        public static FileStream OpenShared(string path)
        {
            try
            {
                return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16);
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException)
            {
                return null;
            }
        }

        private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
        private const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
        private const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
        private const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);
        private const int TRUST_E_EXPLICIT_DISTRUST = unchecked((int)0x800B0111);
        private const int CERT_E_EXPIRED = unchecked((int)0x800B0101);
        private const int CERT_E_REVOKED = unchecked((int)0x800B010C);
        private const int CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109);
        private const int CERT_E_CHAINING = unchecked((int)0x800B010A);

        private const int WTD_UI_NONE = 2;
        private const int WTD_REVOKE_NONE = 0;
        private const int WTD_CHOICE_FILE = 1;
        private const int WTD_CHOICE_CATALOG = 2;
        private const int WTD_STATEACTION_VERIFY = 1;
        private const int WTD_STATEACTION_CLOSE = 2;
        private const int WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public int cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_CATALOG_INFO
        {
            public int cbStruct;
            public int dwCatalogVersion;
            public string pcwszCatalogFilePath;
            public string pcwszMemberTag;
            public string pcwszMemberFilePath;
            public IntPtr hMemberFile;
            public IntPtr pbCalculatedFileHash;
            public int cbCalculatedFileHash;
            public IntPtr pcCatalogContext;
            public IntPtr hCatAdmin;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_DATA
        {
            public int cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public int dwUIChoice;
            public int fdwRevocationChecks;
            public int dwUnionChoice;
            public IntPtr pUnion;
            public int dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public int dwProvFlags;
            public int dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CATALOG_INFO
        {
            public int cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string wszCatalogFile;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr subsystem, string hashAlgorithm, IntPtr strongHashPolicy, int flags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr admin, SafeFileHandle file, ref int hashSize, byte[] hash, int flags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin, byte[] hash, int hashSize, int flags, ref IntPtr previousCatalog);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CryptCATCatalogInfoFromContext(IntPtr catalog, ref CATALOG_INFO info, int flags);

        [DllImport("wintrust.dll")]
        private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin, IntPtr catalog, int flags);

        [DllImport("wintrust.dll")]
        private static extern bool CryptCATAdminReleaseContext(IntPtr admin, int flags);
    }
}
