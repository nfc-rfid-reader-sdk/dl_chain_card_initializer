using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Drawing;
using System.Windows.Forms;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Nist;
using uFR;
using System.Threading;
using System.Runtime.InteropServices;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1.Pkcs;
using X509Extension = Org.BouncyCastle.Asn1.X509.X509Extension;
using System.Net;

namespace uFRSigner
{
    public partial class frmMain : Form
    {
        const UInt32 MIN_UFR_LIB_VERSION = 0x05000003; // bytes from left to right: MSB=MajorVer, MidSB_H=MinorVer, MidSB_L=0, LSB=BuildNum
        const UInt32 MIN_UFR_FW_VERSION = 0x05000007; // bytes from left to right: MSB=MajorVer, MidSB_H=MinorVer, MidSB_L=0, LSB=BuildNum
        string uFR_NotOpenedMessage = "uFR reader not opened.\r\nYou can't work with DL Signer cards.";

        private bool uFR_Opened = false;
        private bool uFR_Selected = false;

        List<DerObjectIdentifier> mSubjectItemsOIDs = new List<DerObjectIdentifier>();
        List<string> mSubjectItems = new List<string>();
        List<DerObjectIdentifier> mExtItemsOIDs = new List<DerObjectIdentifier>();
        List<X509Extension> mExtItems = new List<X509Extension>();

        AsymmetricKeyParameter mPublicKey = null;
        AsymmetricKeyParameter mPrivateKey = null;
        string ECPubKeyStr = "";

        public frmMain()
        {
            InitializeComponent();
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool SetDllDirectory(string lpPathName);

        private void uFrOpen()
        {
            DL_STATUS status;
            UInt32 version = 0;
            byte version_major;
            byte version_minor;
            UInt16 lib_build;
            byte fw_build;

#if WIN64
            string DllPath = @"lib\windows\x86_64"; // for x64 target
#else
            string DllPath = @"lib\windows\x86"; // for x86 target
#endif
            int repeat_cnt = 0;
            bool repeat = true;
            do
            {
                DllPath = @"..\" + DllPath;
                SetDllDirectory(DllPath);
                try
                {
                    version = uFCoder.GetDllVersion();
                    repeat = false;
                }
                catch (System.Exception)
                {
                    ++repeat_cnt;
                }

            } while (repeat && repeat_cnt < 3); // relative path upper folders level search

            if (repeat)
                throw new Exception("Can't find " + uFCoder.DLL_NAME + ".\r\nYou will not be able to work with DL Signer cards.");

            // Check lib version:
            version_major = (byte)version;
            version_minor = (byte)(version >> 8);
            lib_build = (ushort)(version >> 16);

            version = ((UInt32)version_major << 24) | ((UInt32)version_minor << 16) | (UInt32)lib_build;
            if (version < MIN_UFR_LIB_VERSION)
            {
                uFR_NotOpenedMessage = "Wrong uFCoder library version.\r\n"
                    + "You can't work with DL Signer cards.\r\n\r\nUse uFCoder library "
                    + (MIN_UFR_LIB_VERSION >> 24) + "." + ((MIN_UFR_LIB_VERSION >> 16) & 0xFF)
                    + "." + (MIN_UFR_LIB_VERSION & 0xFFFF) + " or higher.";
                throw new Exception("Wrong uFCoder library version.\r\n"
                    + "You can't work with DL Signer cards.\r\n\r\nUse uFCoder library "
                    + (MIN_UFR_LIB_VERSION >> 24) + "." + ((MIN_UFR_LIB_VERSION >> 16) & 0xFF)
                    + "." + (MIN_UFR_LIB_VERSION & 0xFFFF) + " or higher.");
            }

            status = uFCoder.ReaderOpen();
            if (status != DL_STATUS.UFR_OK)
            {
                uFR_NotOpenedMessage = "uFR reader not opened.\r\nYou can't work with DL Signer cards."
                    + "\r\n\r\nTry to connect uFR reader and restart application.";
                throw new Exception("Can't open uFR reader.\r\nYou will not be able to work with DL Signer cards.");
            }

            // Check firmware version:
            status = uFCoder.GetReaderFirmwareVersion(out version_major, out version_minor);
            if (status != DL_STATUS.UFR_OK)
            {
                uFCoder.ReaderClose();
                throw new Exception("Can't open uFR reader.\r\nYou will not be able to work with DL Signer cards.");
            }
            status = uFCoder.GetBuildNumber(out fw_build);
            if (status != DL_STATUS.UFR_OK)
            {
                uFCoder.ReaderClose();
                throw new Exception("Can't open uFR reader.\r\nYou will not be able to work with DL Signer cards.");
            }

            version = ((UInt32)version_major << 24) | ((UInt32)version_minor << 16) | (UInt32)fw_build;
            if (version < MIN_UFR_FW_VERSION)
            {
                uFCoder.ReaderClose();
                uFR_NotOpenedMessage = "Wrong uFR firmware version.\r\n"
                    + "You can't work with DL Signer cards.\r\n\r\nPlease update firmware to "
                    + (MIN_UFR_FW_VERSION >> 24) + "." + ((MIN_UFR_FW_VERSION >> 16) & 0xFF)
                    + "." + (MIN_UFR_FW_VERSION & 0xFFFF) + " or higher.";
                throw new Exception("Wrong uFR firmware version.\r\n"
                    + "You will not be able to work with DL Signer cards.\r\n\r\nPlease update firmware to "
                    + (MIN_UFR_FW_VERSION >> 24) + "." + ((MIN_UFR_FW_VERSION >> 16) & 0xFF)
                    + "." + (MIN_UFR_FW_VERSION & 0xFFFF) + " or higher and restart application.");
            }

            uFR_Opened = true;
        }

        private void frmMain_Load(object sender, EventArgs e)
        {
            try
            {
                uFrOpen();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void frmMain_FormClosed(object sender, FormClosedEventArgs e)
        {
            if (uFR_Selected)
            {
                uFCoder.s_block_deselect(100);
            }
            if (uFR_Opened)
            {
                uFCoder.ReaderClose();
            }
        }

        private DL_STATUS DeleteECKeyPair()
        {
            DL_STATUS status = DL_STATUS.UFR_OK;
            byte key_index = 0;

            try
            {
                if (!uFR_Opened)
                    throw new Exception(uFR_NotOpenedMessage);

                Cursor.Current = Cursors.WaitCursor;

                byte[] aid = Hex.Decode(uFCoder.JCDL_AID);
                byte[] selection_respone = new byte[16];

                status = uFCoder.SetISO14443_4_Mode();
                if (status != DL_STATUS.UFR_OK)
                    throw new Exception(uFCoder.GetErrorDescription(status));
                else
                    uFR_Selected = true;

                status = uFCoder.JCAppSelectByAid(aid, (byte)aid.Length, selection_respone);
                if (status != DL_STATUS.UFR_OK)
                    throw new Exception(uFCoder.GetErrorDescription(status));

                status = uFCoder.JCAppLogin(true, "00000000");
                if (status != DL_STATUS.UFR_OK)
                    throw new Exception(uFCoder.GetErrorDescription(status));

                status = uFCoder.JCAppDeleteEcKeyPair(key_index);
                if (status != DL_STATUS.UFR_OK)
                    throw new Exception(uFCoder.GetErrorDescription(status));

                return DL_STATUS.UFR_OK;
            }
            catch (Exception ex)
            {
                if (((int)status & 0xFFFFC0) == 0x0A63C0)
                {
                    MessageBox.Show("Wrong SO PIN code. Tries remaining: " + ((int)status & 0x3F),
                        "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                else
                {
                    MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    if (status == DL_STATUS.UFR_NO_CARD) ;
                }

                return status;
            }
            finally
            {
                if (uFR_Selected)
                {
                    uFCoder.s_block_deselect(100);
                    uFR_Selected = false;
                }
                Cursor.Current = Cursors.Default;
            }
        }

        public void SignAndStore()
        {
            ECPubKeyStr = "";

            try
            {
                mSubjectItemsOIDs.Clear();
                mSubjectItems.Clear();
                mExtItemsOIDs.Clear();
                mExtItems.Clear();
            }
            catch (Exception ex) { };

            DL_STATUS status = DL_STATUS.UFR_OK;

            status = DeleteECKeyPair();

            if (status != DL_STATUS.UFR_OK)
            {
                return;
            }

            byte key_index = 0;
            byte key_type;
            UInt16 key_size_bits = 256;
            UInt16 component_size_bytes = (UInt16)((key_size_bits + 7) / 8);
            bool isCurveTrinomial;
            byte[] param = null;
            UInt16 param_size = 1; // for r_oversized indicator or (byte)!isCurveTrinomial at index 0
            UInt16 param_offset = 1;
            UInt16 temp;
            byte r_oversized = 0;

            key_type = (byte)JCDL_KEY_TYPES.TYPE_EC_FP_PRIVATE;
            param_size += (UInt16)(component_size_bytes * 6 + 3);

            string tbECParamR = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
            string tbECParamPrime = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
            string tbECParamA = "0000000000000000000000000000000000000000000000000000000000000000";
            string tbECParamB = "0000000000000000000000000000000000000000000000000000000000000007";
            string tbECParamG = "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
            string tbECParamK = "1";

            try
            {
                // Code is logically deliberately dislocated here:
                if (tbECParamR.Length / 2 != component_size_bytes)
                {
                    if (tbECParamR.Length / 2 != component_size_bytes + 1)
                    {
                        throw new Exception("Wrong size of the EC curve parameter R");
                    }
                    else
                    {
                        r_oversized = 1;
                        ++param_size;
                    }
                }
                param = new byte[param_size];
                param[0] = r_oversized;

                if (tbECParamPrime.Length / 2 != component_size_bytes)
                    throw new Exception("Wrong size of the EC curve parameter p");
                Array.Copy(Hex.Decode(tbECParamPrime), 0, param, param_offset, component_size_bytes);
                param_offset += component_size_bytes;

                if (tbECParamA.Length / 2 != component_size_bytes)
                    throw new Exception("Wrong size of the EC curve parameter a");
                Array.Copy(Hex.Decode(tbECParamA), 0, param, param_offset, component_size_bytes);
                param_offset += component_size_bytes;

                if (tbECParamB.Length / 2 != component_size_bytes)
                    throw new Exception("Wrong size of the EC curve parameter b");
                Array.Copy(Hex.Decode(tbECParamB), 0, param, param_offset, component_size_bytes);
                param_offset += component_size_bytes;

                if (tbECParamG.Length / 2 != component_size_bytes * 2 + 1)
                    throw new Exception("Wrong size of the EC curve parameter G(uc)");
                Array.Copy(Hex.Decode(tbECParamG), 0, param, param_offset, component_size_bytes * 2 + 1);
                param_offset += (UInt16)(component_size_bytes * 2 + 1);

                Array.Copy(Hex.Decode(tbECParamR), 0, param, param_offset, component_size_bytes + r_oversized);
                param_offset += (UInt16)(component_size_bytes + r_oversized);

                temp = Convert.ToUInt16(tbECParamK);
                param[param_offset++] = (byte)(temp >> 8);
                param[param_offset] = (byte)temp;

                Cursor.Current = Cursors.WaitCursor;

                byte[] aid = Hex.Decode(uFCoder.JCDL_AID);
                byte[] selection_respone = new byte[16];

                status = uFCoder.SetISO14443_4_Mode();
                if (status != DL_STATUS.UFR_OK)
                    throw new Exception(uFCoder.GetErrorDescription(status));
                else
                    uFR_Selected = true;

                status = uFCoder.JCAppSelectByAid(aid, (byte)aid.Length, selection_respone);
                if (status != DL_STATUS.UFR_OK)
                    throw new Exception(uFCoder.GetErrorDescription(status));

                status = uFCoder.JCAppLogin(true, "00000000");
                if (status != DL_STATUS.UFR_OK)
                    throw new Exception(uFCoder.GetErrorDescription(status));

                status = uFCoder.JCAppGenerateKeyPair(key_type, key_index, 0, key_size_bits, param, param_size);
                if (status != DL_STATUS.UFR_OK)
                    throw new Exception(uFCoder.GetErrorDescription(status));

                DL_STATUS get_status = GetECPublicKeyFromCard();

                if(get_status != DL_STATUS.UFR_OK)
                {
                    uFCoder.s_block_deselect(100);
                    uFR_Selected = false;
                    return;
                }
            }
            catch (Exception ex)
            {
                if (((int)status & 0xFFFFC0) == 0x0A63C0)
                {
                    MessageBox.Show("Wrong SO PIN code. Tries remaining: " + ((int)status & 0x3F),
                        "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                else
                {
                    MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    if (status == DL_STATUS.UFR_NO_CARD) ;
                }

                uFCoder.s_block_deselect(100);
                uFR_Selected = false;

                return;
            }
            finally
            {
                if (uFR_Selected)
                {
                    uFCoder.s_block_deselect(100);
                    uFR_Selected = false;
                }
                Cursor.Current = Cursors.Default;
            }

            PrepareKey();

            if (!saveAs(true))
            {
                return;
            }

            if (!GetCertificateOnline())
            {
                return;
            };

            StoreCertificateInCard();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            SignAndStore();
        }

        private string der2pem(byte[] DerByteArray, string HeaderFooter)
        {
            const int MAX_LINE_LEN = 64;

            string str_out = "-----BEGIN " + HeaderFooter + "-----\r\n";

#pragma warning disable 0162 // Disable "Unreachable code" warning
            if (MAX_LINE_LEN == 76)
                str_out += Convert.ToBase64String(DerByteArray, Base64FormattingOptions.InsertLineBreaks);
            else
            {
                int i = 0;
                string str_tbs = Convert.ToBase64String(DerByteArray);

                while (i < str_tbs.Length)
                {
                    int chunk = (str_tbs.Length - i) < MAX_LINE_LEN ? str_tbs.Length - i : MAX_LINE_LEN;
                    str_out += str_tbs.Substring(i, chunk) + "\r\n";
                    i += chunk;
                }
            }
#pragma warning restore 0162 // Restore "Unreachable code" warning

            str_out += "-----END " + HeaderFooter + "-----\r\n";

            return str_out;
        }

        private bool saveAs(bool Signed)
        {
            //SaveFileDialog dialog;

            mSubjectItemsOIDs.Add(X509Name.C);
            mSubjectItemsOIDs.Add(X509Name.OU);
            mSubjectItemsOIDs.Add(X509Name.CN);
            mSubjectItemsOIDs.Add(X509Name.TelephoneNumber);

            mSubjectItems.Add(CountryCodeTB.Text.Trim());
            mSubjectItems.Add(OrganizationalUnitTB.Text.Trim());
            mSubjectItems.Add(CommonNameTB.Text.Trim());
            mSubjectItems.Add(PhoneNumberTB.Text.Trim());

            mExtItemsOIDs.Add(X509Extensions.SubjectAlternativeName);
            mExtItems.Add(new X509Extension(false,
                new DerOctetString(new GeneralNames(new GeneralName(GeneralName.Rfc822Name, EmailTB.Text)))));


            string mKeyUsageDescription = "digitalSignature, nonRepudiation";

            int key_usage_bit_map = 0;
            key_usage_bit_map |= KeyUsage.DigitalSignature;
            key_usage_bit_map |= KeyUsage.NonRepudiation;

            KeyUsage mKeyUsage = new KeyUsage(key_usage_bit_map);

            mExtItemsOIDs.Add(X509Extensions.KeyUsage);
            mExtItems.Add(new X509Extension(true, new DerOctetString(mKeyUsage)));

            try
            {
                /* dialog = new SaveFileDialog();
                 dialog.Filter = "CSR files (*.pem)|*.pem|All files (*.*)|*.*";
                 dialog.RestoreDirectory = true;*/

                //if (dialog.ShowDialog() == DialogResult.OK)
                //{
                X509Name subject = new X509Name(mSubjectItemsOIDs, mSubjectItems);
                string signatureAlgorithm = "SHA256withECDSA";

                DerSet attributes = new DerSet();
                if (mExtItemsOIDs.Count > 0)
                {
                    attributes.AddObject(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(
                        new X509Extensions(mExtItemsOIDs, mExtItems)))); // mExtItemsOIDs.Zip(mExtItems, (k, v) => new { Key = k, Value = v })
                                                                         //              .ToDictionary(x => x.Key, x => x.Value)
                }

                AsymmetricKeyParameter local_pub_key;

                if (Signed)
                    local_pub_key = mPublicKey;
                else
                    local_pub_key = new RsaKeyParameters(false, BigInteger.One, BigInteger.One); // DUMMY RSA public key - for templates

                Pkcs10CertificationRequestDelaySigned csr_ds =
                    new Pkcs10CertificationRequestDelaySigned(signatureAlgorithm, subject, local_pub_key, attributes);

                byte[] dataToSign = csr_ds.GetDataToSign();
                byte[] toSave;
                string header_footer;

                if (Signed)
                {

                    byte[] SignedData = uFRSigner(dataToSign);
                    // Rest of the input parameters needed (here accessible directly from UI):
                    //      - digest_alg, signature_cipher, card_key_index
                    csr_ds.SignRequest(SignedData);

                    toSave = csr_ds.GetDerEncoded();
                    header_footer = "CERTIFICATE REQUEST";
                }
                else
                {
                    toSave = dataToSign;
                    header_footer = "TBS CERTIFICATE REQUEST";
                }

                var file_extension = Path.GetExtension("CSR.pem");
                if (file_extension.Equals(".pem"))
                {
                    //var textWriter = new StreamWriter(dialog.FileName);
                    var textWriter = new StreamWriter("CSR.pem");

                    textWriter.Write(der2pem(toSave, header_footer));
                    textWriter.Flush();
                    textWriter.Close();
                }
                /* else
                 {
                     using (var fs = new FileStream(dialog.FileName, FileMode.Create, FileAccess.Write))
                     {
                         fs.Write(toSave, 0, toSave.Length);
                         fs.Flush();
                         fs.Close();
                     }
                 }*/
                // }
                //else
                //return false;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            return true;
        }

        public void setParameters(frmMain frmMainInstance, AsymmetricKeyParameter public_key, AsymmetricKeyParameter private_key, byte key_idx, string cipher_name)
        {
            if (public_key != null)
                mPublicKey = public_key;
            else
                mPublicKey = new RsaKeyParameters(false, BigInteger.One, BigInteger.One); // DUMMY RSA public key - for templates

            if (private_key != null)
                mPrivateKey = private_key;
            else
                mPrivateKey = null;
        }

        public void PrepareKey()
        {
            try
            {
                byte key_idx = 0;

                X9ECParameters curve = SecNamedCurves.GetByName("secp256k1");

                AsymmetricKeyParameter pub_key = null;
                pub_key = new ECPublicKeyParameters("ECDSA", curve.Curve.DecodePoint(Hex.Decode(ECPubKeyStr)), SecNamedCurves.GetOid("secp256k1"));

                AsymmetricKeyParameter priv_key = null;

                setParameters(this, pub_key, priv_key, key_idx, "ECDSA");
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        public DL_STATUS GetECPublicKeyFromCard()
        {
            DL_STATUS status = DL_STATUS.UFR_OK;
            byte key_index = 0;
            UInt16 k, key_size_bits, key_designator;
            byte[] keyW, field, a, b, g, r;

            try
            {
                if (!uFR_Opened)
                    throw new Exception(uFR_NotOpenedMessage);
                Cursor.Current = Cursors.WaitCursor;

                byte[] aid = Hex.Decode(uFCoder.JCDL_AID);
                byte[] selection_respone = new byte[16];

                /* status = uFCoder.SetISO14443_4_Mode();
                 if (status != DL_STATUS.UFR_OK)
                     throw new Exception(uFCoder.GetErrorDescription(status));
                 else
                     uFR_Selected = true;

                 status = uFCoder.JCAppSelectByAid(aid, (byte)aid.Length, selection_respone);
                 if (status != DL_STATUS.UFR_OK)
                     throw new Exception(uFCoder.GetErrorDescription(status));*/

                status = uFCoder.JCAppGetEcPublicKey(key_index, out keyW, out field, out a, out b, out g, out r, out k, out key_size_bits, out key_designator);
                if (status != DL_STATUS.UFR_OK)
                    throw new Exception(uFCoder.GetErrorDescription(status));

                ECPubKeyStr = Hex.ToHexString(keyW);

                return DL_STATUS.UFR_OK;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);

                return status;
            }
            finally
            {
                if (uFR_Selected)
                {
                    uFCoder.s_block_deselect(100);
                    uFR_Selected = false;
                }
                Cursor.Current = Cursors.Default;
            }
        }

        private byte[] uFRSigner(byte[] tbs)
        {
            byte key_index = 0;
            byte jc_signer_cipher = 1;
            byte jc_signer_digest = 0;
            byte jc_signer_padding = 0;
            byte[] signature = null;
            byte[] dataToSign = null;
            DL_STATUS status = DL_STATUS.UFR_OK;
            bool uFR_Selected = false;
            UInt16 key_size_bits;

            byte[] hash = DigestUtilities.CalculateDigest("SHA-256", tbs);

            try
            {
                byte[] aid = Hex.Decode(uFCoder.JCDL_AID);
                byte[] selection_respone = new byte[16];

                status = uFCoder.SetISO14443_4_Mode();
                if (status != DL_STATUS.UFR_OK)
                    throw new Exception(uFCoder.GetErrorDescription(status));
                else
                    uFR_Selected = true;

                status = uFCoder.JCAppSelectByAid(aid, (byte)aid.Length, selection_respone);
                if (status != DL_STATUS.UFR_OK)
                    throw new Exception(uFCoder.GetErrorDescription(status));

                status = uFCoder.JCAppLogin(false, "00000000");

                Cursor.Current = Cursors.WaitCursor;

                jc_signer_digest = (byte)uFR.JCDL_SIGNER_DIGESTS.ALG_NULL;
                jc_signer_padding = (byte)JCDL_SIGNER_PADDINGS.PAD_NULL;

                // For ECDSA, first we need key length in bits:
                UInt16 key_designator;
                status = uFCoder.JCAppGetEcKeySizeBits(key_index, out key_size_bits, out key_designator);
                if (status != DL_STATUS.UFR_OK)
                    throw new Exception(uFCoder.GetErrorDescription(status));

                // ECDSA hash alignment before signing:
                dataToSign = Enumerable.Repeat((byte)0, (key_size_bits + 7) / 8).ToArray();
                if (dataToSign.Length > hash.Length)
                    //Array.Copy(hash, 0, to_be_signed, to_be_signed.Length - hash.Length, hash.Length);
                    dataToSign = hash; // Can be done on J3H145 because supporting Cipher.PAD_NULL with Signature.SIG_CIPHER_ECDSA 
                else // in case of (to_be_signed.Length <= hash.Length)
                {
                    Array.Copy(hash, 0, dataToSign, 0, dataToSign.Length);
                    if ((key_size_bits % 8) != 0)
                    {
                        byte prev_byte = 0;
                        byte shift_by = (byte)(key_size_bits % 8);

                        for (int i = 0; i < dataToSign.Length; i++)
                        {
                            byte temp = dataToSign[i];
                            dataToSign[i] >>= 8 - shift_by;
                            dataToSign[i] |= prev_byte;
                            prev_byte = temp <<= shift_by;
                        }
                    }
                }


                if (dataToSign.Length > uFCoder.SIG_MAX_PLAIN_DATA_LEN)
                {
                    int chunk_len, src_pos, rest_of_data;
                    byte[] chunk = new byte[uFCoder.SIG_MAX_PLAIN_DATA_LEN];

                    rest_of_data = dataToSign.Length - (int)uFCoder.SIG_MAX_PLAIN_DATA_LEN;
                    src_pos = (int)uFCoder.SIG_MAX_PLAIN_DATA_LEN;
                    chunk_len = (int)uFCoder.SIG_MAX_PLAIN_DATA_LEN;
                    Array.Copy(dataToSign, 0, chunk, 0, chunk_len);

                    status = uFCoder.JCAppSignatureBegin(jc_signer_cipher, jc_signer_digest, jc_signer_padding,
                                                        key_index, chunk, (UInt16)chunk_len,
                                                        null, 0);
                    if (status != DL_STATUS.UFR_OK)
                        throw new Exception(uFCoder.GetErrorDescription(status));

                    while (rest_of_data > 0)
                    {
                        chunk_len = rest_of_data > uFCoder.SIG_MAX_PLAIN_DATA_LEN ? (int)uFCoder.SIG_MAX_PLAIN_DATA_LEN : rest_of_data;
                        Array.Copy(dataToSign, src_pos, chunk, 0, chunk_len);

                        status = uFCoder.JCAppSignatureUpdate(chunk, (UInt16)chunk_len);
                        if (status != DL_STATUS.UFR_OK)
                            throw new Exception(uFCoder.GetErrorDescription(status));

                        src_pos += chunk_len;
                        rest_of_data -= chunk_len;
                    }

                    status = uFCoder.JCAppSignatureEnd(out signature);
                    if (status != DL_STATUS.UFR_OK)
                        throw new Exception(uFCoder.GetErrorDescription(status));
                }
                else
                {
                    status = uFCoder.JCAppGenerateSignature(jc_signer_cipher, jc_signer_digest, jc_signer_padding,
                                                            key_index,
                                                            dataToSign, (UInt16)dataToSign.Length,
                                                            out signature,
                                                            null, 0);
                    if (status != DL_STATUS.UFR_OK)
                        throw new Exception(uFCoder.GetErrorDescription(status));
                }

                // In case of ECDSA signature, last 2 bytes are ushort value representing the key_size in bits
                int len = signature.Length;
                key_size_bits = (UInt16)(((UInt16)signature[len - 2] << 8) | signature[len - 1]);
                int key_size_bytes = (key_size_bits + 7) / 8;
                byte[] der_sig = new byte[len - 2];
                Array.Copy(signature, der_sig, len - 2);

                signature = DLogicAsn1Tools.fixEccSignatureSequence(der_sig);

            }
            finally
            {
                Cursor.Current = Cursors.Default;

                if (uFR_Selected)
                {
                    uFCoder.s_block_deselect(100);
                    uFR_Selected = false;
                }
            }

            return signature;
        }

        public static string generateRandomString(int length)
        {
            Random random = new Random();
            string characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            StringBuilder result = new StringBuilder(length);
            for (int i = 0; i < length; i++)
            {
                result.Append(characters[random.Next(characters.Length)]);
            }
            return result.ToString();
        }

        public bool GetCertificateOnline()
        {
            string url = File.ReadAllText("hosturl.txt").Trim();

            byte[] buffer = new byte[1024 * 8];
            int bytesRead = 0;
            int bytesTotal = 0;

            WebResponse response = null;
            Stream remoteStream = null;
            Stream localStream = null;
            FileStream fileStream = null;
            string randomFileName = null;

                try
                {
                    // Create a http request to the server endpoint that will pick up the file and file description:
                    HttpWebRequest requestToServerEndpoint = (HttpWebRequest)WebRequest.Create(url);
                    //requestToServerEndpoint.Timeout = 1000;

                    string boundaryString = generateRandomString(20);

                    // Set the http request header:
                    requestToServerEndpoint.Method = WebRequestMethods.Http.Post;
                    requestToServerEndpoint.ContentType = "multipart/form-data; boundary=" + boundaryString;
                    requestToServerEndpoint.KeepAlive = true;
                    requestToServerEndpoint.Credentials = System.Net.CredentialCache.DefaultCredentials;

                    // Use a MemoryStream to form the post data request, so that we can get the content-length attribute.
                    MemoryStream postDataStream = new MemoryStream();
                    StreamWriter postDataWriter = new StreamWriter(postDataStream);

                    // Include the file in the post data:
                    postDataWriter.Write("\r\n--" + boundaryString + "\r\n");
                    postDataWriter.Write("Content-Disposition: form-data; name=\"file\"; filename=\"{0}\"\r\n", Path.GetFileName("CSR.pem"));
                    postDataWriter.Write("Content-Type: application/octet-stream\r\n\r\n");
                    postDataWriter.Flush();

                    // Write file binary in the post data:
                    fileStream = new FileStream("CSR.pem", FileMode.Open, FileAccess.Read);
                    while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) != 0)
                    {
                        postDataStream.Write(buffer, 0, bytesRead);
                    }
                    fileStream.Close();
                    fileStream = null;

                    // Include JSON params in the post data:
                    postDataWriter.Write("\r\n--" + boundaryString + "\r\n");
                    postDataWriter.Write("Content-Disposition: form-data; name=\"query\"\r\n\r\n");
                    postDataWriter.Write("{\"operation\":\"verify\",\"user_id\":0,\"security_token\":\"\"}");
                    postDataWriter.Write("\r\n--" + boundaryString + "--\r\n");
                    postDataWriter.Flush();

                    // Set the http request body content length
                    requestToServerEndpoint.ContentLength = postDataStream.Length;

                    // Dump the post data from the memory stream to the request stream:
                    using (Stream s = requestToServerEndpoint.GetRequestStream())
                    {
                        postDataStream.WriteTo(s);
                    }
                    postDataStream.Close();

                    // Grab the response from the server. WebException will be thrown when a HTTP OK status is not returned.
                    response = requestToServerEndpoint.GetResponse();

                    // response.Headers.Get("x123")

                    if (response.ContentType == "application/json")
                    {
                        // Resolve Error:
                        StreamReader responseReader = new StreamReader(response.GetResponseStream());
                        string replyFromServer = responseReader.ReadToEnd();
                        throw new Exception(replyFromServer);
                    }
                    else if (response.ContentType == "application/octet-stream")
                    {
                        // Save certificate file:
                        do
                        {
                            randomFileName = Path.GetTempPath() + generateRandomString(8) + ".pem";
                        } while (File.Exists(randomFileName));

                        // Create the temporary local file
                        localStream = File.Create(randomFileName);

                        // Simple do-while loop to read from stream until no bytes are returned:
                        do
                        {
                            // Read data from the stream:
                            remoteStream = response.GetResponseStream();
                            bytesRead = remoteStream.Read(buffer, 0, buffer.Length);

                            // Write the data to the temporary local file
                            localStream.Write(buffer, 0, bytesRead);

                            // Increment total bytes processed
                            bytesTotal += bytesRead;
                        } while (bytesRead > 0);

                        if (bytesTotal != response.ContentLength)
                            throw new Exception("Wrong certificate file length");

                        localStream.Close();
                        localStream = null;

                        // Save dialog to finally move temporary local file content:
                        SaveFileDialog saveDialog = new SaveFileDialog();
                        saveDialog.Title = "New X.509 certificate is successfully issued. Please select PEM file to save the certificate.";
                        saveDialog.Filter = "X.509 Certificate files (*.pem)|*.pem|All files (*.*)|*.*";
                        saveDialog.RestoreDirectory = true;
                        saveDialog.FileName = "certificate.pem";

                            if (File.Exists("certificate.pem"))
                            {
                                File.Delete("certificate.pem");
                            }
                            File.Copy(randomFileName, "certificate.pem");
                    }

                    else
                        throw new Exception("Wrong response from server");

                    return true;
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);

                    return false;
                }
                finally
                {
                    if (response != null) response.Close();
                    if (remoteStream != null) remoteStream.Close();
                    if (localStream != null) localStream.Close();
                    if (fileStream != null) fileStream.Close();
                    if (randomFileName != null && File.Exists(randomFileName))
                    {
                        File.Delete(randomFileName);
                        randomFileName = null;
                    }
                }
        }

        public void StoreCertificateInCard()
        {
            DL_STATUS status = DL_STATUS.UFR_OK;
            byte obj_type = 1;
            byte obj_index = 0;
            X509Certificate2 cert = null;

            if (!(File.Exists("certificate.pem") && Path.HasExtension(".pem")))
            {
                MessageBox.Show("Invalid certificate file name and / or path.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            try
            {
                Cursor.Current = Cursors.WaitCursor;

                if (!uFR_Opened)
                    throw new Exception(uFR_NotOpenedMessage);

                string file_ext = Path.GetExtension("certificate.pem");

                cert = new X509Certificate2("certificate.pem");

                // Should remove any private key from cert:
                if (cert.HasPrivateKey)
                {
                    cert = new X509Certificate2(cert.Export(X509ContentType.Cert));
                }

                byte[] raw_cert = cert.Export(X509ContentType.Cert);
                if (raw_cert == null || raw_cert.Length == 0)
                    throw new Exception("Invalid certificate");
                byte[] raw_subject = cert.SubjectName.RawData;
                if (raw_subject == null || raw_subject.Length == 0)
                    throw new Exception("Invalid certificate");
                byte[] raw_id = Encoding.ASCII.GetBytes("1001");
                if (raw_id.Length == 0)
                    throw new Exception("Invalid Id");

                // Open JCApp:
                byte[] aid = Hex.Decode(uFCoder.JCDL_AID);
                byte[] selection_respone = new byte[16];

                status = uFCoder.SetISO14443_4_Mode();
                if (status != DL_STATUS.UFR_OK)
                    throw new Exception(uFCoder.GetErrorDescription(status));
                else
                    uFR_Selected = true;

                status = uFCoder.JCAppSelectByAid(aid, (byte)aid.Length, selection_respone);
                if (status != DL_STATUS.UFR_OK)
                    throw new Exception(uFCoder.GetErrorDescription(status));

                status = uFCoder.JCAppLogin(true, "00000000");
                if (status != DL_STATUS.UFR_OK)
                    throw new Exception(uFCoder.GetErrorDescription(status));

                status = uFCoder.JCAppPutObj(obj_type, obj_index, raw_cert, (UInt16)raw_cert.Length, raw_id, (byte)raw_id.Length);
                if (status != DL_STATUS.UFR_OK)
                    throw new Exception(uFCoder.GetErrorDescription(status));

                status = uFCoder.JCAppPutObjSubject(obj_type, obj_index, raw_subject, (byte)raw_subject.Length);
                if (status != DL_STATUS.UFR_OK)
                    throw new Exception(uFCoder.GetErrorDescription(status));

                if (uFR_Selected)
                {
                    uFR_Selected = false;
                    uFCoder.s_block_deselect(100);
                }

                MessageBox.Show("The certificate has been successfully stored.", "Sucess", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                if (((int)status & 0xFFFFC0) == 0x0A63C0)
                {
                    MessageBox.Show("Wrong SO PIN code. Tries remaining: " + ((int)status & 0x3F),
                        "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                else
                {
                    MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            finally
            {
                if (uFR_Selected)
                {
                    uFCoder.s_block_deselect(100);
                    uFR_Selected = false;
                }
                Cursor.Current = Cursors.Default;
            }
        }
    }
}