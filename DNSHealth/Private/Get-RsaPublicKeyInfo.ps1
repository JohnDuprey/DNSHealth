function Get-RsaPublicKeyInfo {
    <#
    .SYNOPSIS
    Gets RSA public key info from Base64 string

    .DESCRIPTION
    Decodes RSA public key information for validation. Uses a c# library to decode base64 data.

    .PARAMETER EncodedString
    Base64 encoded public key string

    .EXAMPLE
    PS> Get-RsaPublicKeyInfo -EncodedString <base64 string>

    LegalKeySizes                           KeyExchangeAlgorithm SignatureAlgorithm KeySize
    -------------                           -------------------- ------------------ -------
    {System.Security.Cryptography.KeySizes} RSA                  RSA                   2048

    .NOTES
    Obtained C# code from https://github.com/sevenTiny/Bamboo/blob/b5503b5597383ca6085ceb4aa5fa054918a4bd73/10-Code/SevenTiny.Bantina/Security/RSACommon.cs
    #>
    Param(
        [Parameter(Mandatory = $true)]
        $EncodedString
    )
    $source = @'
/*********************************************************
 * CopyRight: 7TINY CODE BUILDER.
 * Version: 5.0.0
 * Author: 7tiny
 * Address: Earth
 * Create: 2018-04-08 21:54:19
 * Modify: 2018-04-08 21:54:19
 * E-mail: dong@7tiny.com | sevenTiny@foxmail.com
 * GitHub: https://github.com/sevenTiny
 * Personal web site: http://www.7tiny.com
 * Technical WebSit: http://www.cnblogs.com/7tiny/
 * Description:
 * Thx , Best Regards ~
 *********************************************************/
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SevenTiny.Bantina.Security {
    public static class RSACommon {
        public static RSA CreateRsaProviderFromPublicKey(string publicKeyString)
        {
            // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
            byte[] seqOid = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            byte[] seq = new byte[15];

            var x509Key = Convert.FromBase64String(publicKeyString);

            // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
            using (MemoryStream mem = new MemoryStream(x509Key))
            {
                using (BinaryReader binr = new BinaryReader(mem))  //wrap Memory Stream with BinaryReader for easy reading
                {
                    byte bt = 0;
                    ushort twobytes = 0;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8230)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    seq = binr.ReadBytes(15);       //read the Sequence OID
                    if (!CompareBytearrays(seq, seqOid))    //make sure Sequence for OID is correct
                        return null;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8103) //data read as little endian order (actual data order for Bit String is 03 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8203)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    bt = binr.ReadByte();
                    if (bt != 0x00)     //expect null byte next
                        return null;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8230)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    twobytes = binr.ReadUInt16();
                    byte lowbyte = 0x00;
                    byte highbyte = 0x00;

                    if (twobytes == 0x8102) //data read as little endian order (actual data order for Integer is 02 81)
                        lowbyte = binr.ReadByte();  // read next bytes which is bytes in modulus
                    else if (twobytes == 0x8202)
                    {
                        highbyte = binr.ReadByte(); //advance 2 bytes
                        lowbyte = binr.ReadByte();
                    }
                    else
                        return null;
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };   //reverse byte order since asn.1 key uses big endian order
                    int modsize = BitConverter.ToInt32(modint, 0);

                    int firstbyte = binr.PeekChar();
                    if (firstbyte == 0x00)
                    {   //if first byte (highest order) of modulus is zero, don't include it
                        binr.ReadByte();    //skip this null byte
                        modsize -= 1;   //reduce modulus buffer size by 1
                    }

                    byte[] modulus = binr.ReadBytes(modsize);   //read the modulus bytes

                    if (binr.ReadByte() != 0x02)            //expect an Integer for the exponent data
                        return null;
                    int expbytes = (int)binr.ReadByte();        // should only need one byte for actual exponent data (for all useful values)
                    byte[] exponent = binr.ReadBytes(expbytes);

                    // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                    var rsa = System.Security.Cryptography.RSA.Create();
                    RSAParameters rsaKeyInfo = new RSAParameters
                    {
                        Modulus = modulus,
                        Exponent = exponent
                    };
                    rsa.ImportParameters(rsaKeyInfo);

                    return rsa;
                }
            }
        }
        private static bool CompareBytearrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;
            int i = 0;
            foreach (byte c in a)
            {
                if (c != b[i])
                    return false;
                i++;
            }
            return true;
        }
    }
}
'@
    try {
        if (!('SevenTiny.Bantina.Security.RSACommon' -as [type])) {
            Add-Type -TypeDefinition $source -Language CSharp
        }
    }

    catch { Write-Verbose $_.Exception.Message }

    # Return RSA Public Key information
    [SevenTiny.Bantina.Security.RSACommon]::CreateRsaProviderFromPublicKey($EncodedString)
}
