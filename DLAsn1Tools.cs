using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace uFRSigner
{
    class DLogicAsn1Tools
    {
        //------------------------------------------------------------------------------
        const UInt32 ASN1_MAX_LEN_BYTES = 4;
        //------------------------------------------------------------------------------

        public static bool asn1DecodeLength(byte[] bx, ref UInt32 len, out UInt32 len_bytes)
        {

            len_bytes = 0;

            if ((bx[0] & 0x80) != 0x80)
            {
                len_bytes = 1;
                len = bx[0];
                return true;
            }

            len_bytes = (UInt32)bx[0] & 0x7F;

            if (len_bytes > ASN1_MAX_LEN_BYTES)
            {
                len_bytes = 0;
                return false;
            }

            if ((len_bytes < (ASN1_MAX_LEN_BYTES + 1)) && (len_bytes > 0))
            {
                // Big Endian decoding:
                for (int i = (Int32)len_bytes; i > 0; i--)
                {
                    len |= (uint)bx[i] << (8 * ((byte)len_bytes - i));
                }
            }
            else
            {
                len_bytes = 0;
                return false;
            }

            len_bytes += 1;
            return true;
        }

        private static byte[] removeArrItemAt(byte[] inArr, int idx)
        {
            byte[] res = new byte[inArr.Length - 1];

            inArr.Take(idx + 1).ToArray().CopyTo(res, 0);
            inArr.Skip(idx + 1).ToArray().CopyTo(res, idx);

            return res;
        }

        public static byte[] fixEccSignatureSequence(byte[] der_sig)
        {
            byte[] res = der_sig.ToArray();
            int der_idx = 0, der_tmp_idx;
            uint der_len = 0, der_len_len, der_seq_len_len;

            if (res[der_idx++] != 0x30)
                throw new Exception("ASN.1 DER signature format error");
            if (!asn1DecodeLength(res.Skip(der_idx).ToArray(), ref der_len, out der_len_len))
                throw new Exception("ASN.1 DER signature format error");

            der_seq_len_len = der_len_len;

            der_idx += (int)der_len_len;
            if (res[der_idx++] != 2)
                throw new Exception("ASN.1 DER signature format error");
            der_tmp_idx = der_idx; // Points to a length TLV field
            if (!asn1DecodeLength(res.Skip(der_idx).ToArray(), ref der_len, out der_len_len))
                throw new Exception("ASN.1 DER signature format error");
            der_idx += (int)der_len_len;
            if ((res[der_idx] == 0) && ((res[der_idx + 1] & 0x80) == 0))
            {
                res = removeArrItemAt(res, der_idx);
                --der_len;
                if (der_len_len != 1)
                    throw new Exception("ASN.1 DER signature format error-");
                --res[der_tmp_idx];
                --res[der_seq_len_len];
            }
            der_idx += (int)der_len;
            if (res[der_idx++] != 2)
                throw new Exception("ASN.1 DER signature format error");
            der_tmp_idx = der_idx; // Points to a length TLV field
            if (!asn1DecodeLength(res.Skip(der_idx).ToArray(), ref der_len, out der_len_len))
                throw new Exception("ASN.1 DER signature format error");
            der_idx += (int)der_len_len;
            if ((res[der_idx] == 0) && ((res[der_idx + 1] & 0x80) == 0))
            {
                res = removeArrItemAt(res, der_idx);
                if (der_len_len != 1)
                    throw new Exception("ASN.1 DER signature format error--");
                --res[der_tmp_idx];
                --res[der_seq_len_len];
            }

            return res;
        }
    }
}
