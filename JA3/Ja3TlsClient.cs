﻿using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;

namespace JA3Test
{
    public class Ja3TlsClient : AbstractTlsClient
    {
        internal TlsSession m_session;
        private ServerName[] _serverNames;
        public bool EnableHttp2 { get; set; } = false;


        public string[] ServerNames
        {
            set
            {
                if (value == null)
                {
                    _serverNames = null;
                }
                else
                {
                    _serverNames = value.Select(x => new ServerName(NameType.host_name, Encoding.ASCII.GetBytes(x))).ToArray();
                }
            }
        }


        public Ja3TlsClient(TlsSession session)
            : base(new BcTlsCrypto(new SecureRandom()))
        {
            this.m_session = session;


        }

        public IList<SignatureAndHashAlgorithm> SignatureAlgorithms { get; set; } = new[] {
            CreateSignatureAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256),
            CreateSignatureAlgorithm(SignatureScheme.rsa_pss_rsae_sha256),
            CreateSignatureAlgorithm(SignatureScheme.rsa_pkcs1_sha256),
            CreateSignatureAlgorithm(SignatureScheme.ecdsa_secp384r1_sha384),
            CreateSignatureAlgorithm(SignatureScheme.rsa_pss_rsae_sha384),
            CreateSignatureAlgorithm(SignatureScheme.rsa_pkcs1_sha384),
            CreateSignatureAlgorithm(SignatureScheme.rsa_pss_rsae_sha512),
            CreateSignatureAlgorithm(SignatureScheme.rsa_pkcs1_sha512),
            CreateSignatureAlgorithm(SignatureScheme.rsa_pkcs1_sha1),
        };

        public int[] SupportedCiphers { get; set; } = new[] {
            4865,4866,4867,49195,49199,49196,49200,52393,52392,49171,49172,156,157,47,53
            //0xc02c,
            //0xc02b,0xc030,0xc02f,0x009f,0x009e,0xc024,0xc023,0xc028,0xc027,0xc00a,0xc009,0xc014,0xc013,0x009d,0x009c,0x003d,0x003c,0x0035,0x002f,0x000a
            //CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            //CipherSuite.TLS_AES_128_GCM_SHA256,
            //CipherSuite.TLS_AES_256_GCM_SHA384,
            //CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            //CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            //CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            //CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            //CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            //CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            //CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            //CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            //CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            //CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            //CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            //CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
            //CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            //CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
            //CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            //CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        };


        public int[] SupportedGroups { get; set; } = new[] {
            //0
            //0x001d,0x001e,0x0017,0x0018,0x0100,0x0101,0x0102
            NamedGroup.x25519,
            NamedGroup.secp256r1,
            NamedGroup.secp384r1,
        };




        public override TlsSession GetSessionToResume()
        {
            return m_session;
        }
        public override TlsAuthentication GetAuthentication()
        {
            return new Ja3TlsAuthentication(m_context);
        }

        public ProtocolVersion[] SupportedVersions { get; set; } = ProtocolVersion.TLSv13.DownTo(ProtocolVersion.TLSv12);
        //public ProtocolVersion[] SupportedVersions { get; set; } = new ProtocolVersion[] { ProtocolVersion.TLSv12 };


        public override void NotifyServerVersion(ProtocolVersion serverVersion)
        {
            base.NotifyServerVersion(serverVersion);
            //Console.WriteLine("TLS client negotiated " + serverVersion);
        }

        public override IList<TlsPskExternal> GetExternalPsks()
        {
            byte[] identity = Strings.ToUtf8ByteArray("client");
            TlsSecret key = Crypto.CreateSecret(Strings.ToUtf8ByteArray("TLS_TEST_PSK"));
            int prfAlgorithm = PrfAlgorithm.tls13_hkdf_sha256;
            //return (IList<TlsPskExternal>)TlsUtilities.VectorOfOne(new BasicTlsPskExternal(identity, key, prfAlgorithm));
            return TlsUtilities.VectorOfOne(new BasicTlsPskExternal(identity, key, prfAlgorithm)).Select(o => (TlsPskExternal)o).ToList();
        }

        //扩展
        public override IDictionary<int, byte[]> GetClientExtensions()
        {
            //chrome:771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,29-23-24,0
            var clientExtensions = TlsExtensionsUtilities.EnsureExtensionsInitialised(base.GetClientExtensions());

            TlsExtensionsUtilities.AddMaxFragmentLengthExtension(clientExtensions, MaxFragmentLength.pow2_9);
            TlsExtensionsUtilities.AddPaddingExtension(clientExtensions, m_context.Crypto.SecureRandom.Next(16));
            TlsExtensionsUtilities.AddTruncatedHmacExtension(clientExtensions);
            TlsExtensionsUtilities.AddRecordSizeLimitExtension(clientExtensions, 16385);
            TlsExtensionsUtilities.AddPaddingExtension(clientExtensions, 0);
            TlsExtensionsUtilities.AddCompressCertificateExtension(clientExtensions, [2]);
            TlsExtensionsUtilities.AddSupportedVersionsExtensionClient(clientExtensions, SupportedVersions);
            TlsExtensionsUtilities.AddStatusRequestExtension(clientExtensions, new CertificateStatusRequest(1, new OcspStatusRequest(new List<ResponderID>(), null)));
            TlsExtensionsUtilities.AddExtendedMasterSecretExtension(clientExtensions);
            TlsExtensionsUtilities.AddPskKeyExchangeModesExtension(clientExtensions, new short[] { 1, 1 });
            TlsExtensionsUtilities.AddKeyShareClientHello(clientExtensions, new List<KeyShareEntry>() { new KeyShareEntry(29, Encoding.ASCII.GetBytes(Guid.NewGuid().ToString()).Take(32).ToArray()) });
            //TlsExtensionsUtilities.AddStatusRequestaddV2Extension(clientExtensions,  new List<CertificateStatusRequestItemV2>() { new CertificateStatusRequestItemV2(1,new OcspStatusRequest(new List<ResponderID>(),null)) });
            //TlsExtensionsUtilities.AddEmptyExtensionData(clientExtensions, 0);
            //TlsExtensionsUtilities.enc(clientExtensions, [2]);

            bool offeringTlsV13Plus = false;
            ProtocolVersion[] supportedVersions = GetProtocolVersions();
            for (int i = 0; i < supportedVersions.Length; ++i)
            {
                var supportedVersion = supportedVersions[i];
                if (TlsUtilities.IsTlsV13(supportedVersion))
                {
                    offeringTlsV13Plus = true;
                }
            }
            if (offeringTlsV13Plus)
            {
                int[] offeredCipherSuites = this.GetCipherSuites();
                TlsPskExternal[] psks = GetPskExternalsClient(this, offeredCipherSuites);
                var identities = new List<PskIdentity>(psks.Length);
                for (int i = 0; i < psks.Length; ++i)
                {
                    TlsPsk psk = psks[i];

                    // TODO[tls13-psk] Handle obfuscated_ticket_age for resumption PSKs
                    identities.Add(new PskIdentity(psk.Identity, 0L));
                }
                TlsExtensionsUtilities.AddPreSharedKeyClientHello(clientExtensions, new OfferedPsks(identities));

            }
            clientExtensions[ExtensionType.renegotiation_info] = TlsUtilities.EncodeOpaque8(TlsUtilities.EmptyBytes);
            //next_protocol_negotiation
            //clientExtensions[13172] = new byte[0];
            //17513 extensionApplicationSettings
            clientExtensions[17513] = new byte[0];


            //return clientExtensions;
            var exts = new Dictionary<int, byte[]>();
            /* net8
            exts[0] = clientExtensions[0];
            exts[10] = clientExtensions[10];
            exts[11] = clientExtensions[11];
            exts[13] = clientExtensions[13];
            exts[35] = new byte[0];
            exts[23] = new byte[0];
            exts[65281] = clientExtensions[65281];
            */

            exts[0] = clientExtensions[0];
            //exts[5] = new byte[5] { 1, 0, 0, 0, 0 };//status_request
            exts[5] = clientExtensions[5];
            exts[10] = clientExtensions[10];
            exts[11] = clientExtensions[11];
            exts[13] = clientExtensions[13];
            if(EnableHttp2)
                 exts[16] = new byte[14] { 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31 };//http2.0
            exts[18] = new byte[0];//signed_certificate_timestamp

            exts[23] = clientExtensions[23];//extended_master_secret

            //exts[23] = new byte[0];//extended_master_secret
            //compress_certificate=27
            exts[27] = clientExtensions[27];
            //exts[27] = new byte[3] { 0x02, 0x00, 0x02 };
            exts[35] = new byte[0];//session_ticket 
            /*
             * 
             * Supported Versions length: 6
                Supported Version: Reserved (GREASE) (0x0a0a)
                Supported Version: TLS 1.3 (0x0304)
                Supported Version: TLS 1.2 (0x0303)
             */

            exts[43] = clientExtensions[43];
            //exts[43] = new byte[7] { 0x06, 0x9a, 0x9a, 0x03, 0x04, 0x03, 0x03 };//43supported_versions
            exts[45] = clientExtensions[45];
            //exts[45] = new byte[2] { 0x01, 0x01 };//psk_key_exchange_modes
            //exts[51] = new byte[43] { 0x00, 0x29, 0x4a, 0x4a, 0x00, 0x01, 0x00, 0x00, 0x1d, 0x00, 0x20, 0x65, 0x91, 0xb6,//key_share
            //    0xec, 0x93, 0x4e, 0xc8, 0x80, 0xef, 0x22, 0xa1, 0xe1, 0x50, 0x1f, 0xbd, 0xdb, 0xfd, 0x6f, 0x21, 0xe6, 0x5d, 0x75, 0xcc, 0x49, 0xed, 0x24, 0x1a, 0xc0, 0xfd, 0xac, 0xeb, 0x64 };
            exts[51] = clientExtensions[51];
            exts[17513] = new byte[5] { 0x00, 0x03, 0x02, 0x68, 0x32 };// application_settings
            //encrypted_client_hello=65037
            //exts[65037] = new byte[0] { };


            /*
             * 
             *  Extension: encrypted_client_hello (len=186)
                Type: encrypted_client_hello (65037)
                Length: 186
                Client Hello type: Outer Client Hello (0)
                Cipher Suite: HKDF-SHA256/AES-128-GCM
                    KDF Id: HKDF-SHA256 (1)
                    AEAD Id: AES-128-GCM (1)
                Config Id: 234
                Enc length: 32
                Enc: 98930f558c729cc8ed7cbeba1e9277a4682ca8b07a8c4502b20331f3fe6ddb29
                Payload length: 144
                Payload [truncated]: 
             *
             * 
             * 
             */
            exts[65037] = new byte[] {
                0x00,// Outer Client Hello (0)
                0x00,0x01, 0x00, 0x01,//HKDF-SHA256/AES-128-GCM
                0xea,//Config Id: 234
                0x00,0x20,//Enc length: 32
                0x98, 0x93, 0x0f, 0x55, 0x8c, 0x72, 0x9c, 0xc8, 0xed, 0x7c, 0xbe, 0xba, 0x1e, 0x92, 0x77, 0xa4, 0x68, 0x2c, 0xa8, 0xb0, 0x7a, 0x8c, 0x45, 0x02, 0xb2, 0x03, 0x31, 0xf3, 0xfe, 0x6d, 0xdb, 0x29,//Enc
                0x00,0x00//Payload length: 0
            };

            var exs2 = exts.OrderBy(o => Guid.NewGuid()).ToDictionary(o => o.Key, v => v.Value);

            exs2[65281] = clientExtensions[65281];//renegotiation_info
            return exs2;
        }

        internal static TlsPskExternal[] GetPskExternalsClient(TlsClient client, int[] offeredCipherSuites)
        {
            var externalPsks = client.GetExternalPsks();
            if (externalPsks == null || externalPsks.Count < 1)
            {
                return null;
            }

            int[] prfAlgorithms = GetPrfAlgorithms13(offeredCipherSuites);

            int count = externalPsks.Count;
            TlsPskExternal[] result = new TlsPskExternal[count];

            for (int i = 0; i < count; ++i)
            {
                TlsPskExternal pskExternal = externalPsks[i] as TlsPskExternal;
                if (null == pskExternal)
                    throw new TlsFatalAlert(AlertDescription.internal_error,
                        "External PSKs element is not a TlsPSKExternal");

                if (!Arrays.Contains(prfAlgorithms, pskExternal.PrfAlgorithm))
                    throw new TlsFatalAlert(AlertDescription.internal_error,
                        "External PSK incompatible with offered cipher suites");

                result[i] = pskExternal;
            }

            return result;
        }


        internal static int[] GetPrfAlgorithms13(int[] cipherSuites)
        {
            int[] result = new int[System.Math.Min(3, cipherSuites.Length)];

            int count = 0;
            for (int i = 0; i < cipherSuites.Length; ++i)
            {
                int prfAlgorithm = GetPrfAlgorithm13(cipherSuites[i]);
                if (prfAlgorithm >= 0 && !Arrays.Contains(result, prfAlgorithm))
                {
                    result[count++] = prfAlgorithm;
                }
            }

            return Truncate(result, count);
        }

        internal static int GetPrfAlgorithm13(int cipherSuite)
        {
            // NOTE: GetPrfAlgorithms13 relies on the number of distinct return values
            switch (cipherSuite)
            {
                case CipherSuite.TLS_AES_128_CCM_SHA256:
                case CipherSuite.TLS_AES_128_CCM_8_SHA256:
                case CipherSuite.TLS_AES_128_GCM_SHA256:
                case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
                    return PrfAlgorithm.tls13_hkdf_sha256;

                case CipherSuite.TLS_AES_256_GCM_SHA384:
                    return PrfAlgorithm.tls13_hkdf_sha384;

                case CipherSuite.TLS_SM4_CCM_SM3:
                case CipherSuite.TLS_SM4_GCM_SM3:
                    return PrfAlgorithm.tls13_hkdf_sm3;

                default:
                    return -1;
            }
        }
        internal static int[] Truncate(int[] a, int n)
        {
            if (n >= a.Length)
                return a;

            int[] t = new int[n];
            Array.Copy(a, 0, t, 0, n);
            return t;
        }

        internal static short[] Truncate(short[] a, int n)
        {
            if (n >= a.Length)
                return a;

            short[] t = new short[n];
            Array.Copy(a, 0, t, 0, n);
            return t;
        }
        public static int[] GetClientExtensionSequence()
        {
            return new int[] {
                ExtensionType.renegotiation_info,       //(65281)
                ExtensionType.server_name,              //(0)
                ExtensionType.extended_master_secret,   //(23)
                ExtensionType.session_ticket,           //(35)
                ExtensionType.signature_algorithms,     //(13)
                ExtensionType.status_request,           //(5)
                13172,//(13172) ExtensionType.next_protocol_negotiation
                ExtensionType.signed_certificate_timestamp,             //(18)
                ExtensionType.application_layer_protocol_negotiation,   //(16)
                ExtensionType.ec_point_formats,         //(11)
                ExtensionType.supported_groups,         //(10)
                ExtensionType.padding,                  //(21) [align 512]
            };
        }

        public int GetExtensionOrder(int type, int[] sequence)
        {
            for (var i = 0; i < sequence.Length; i++)
                if (sequence[i] == type)
                    return i;
            return -1;
        }

        public static IDictionary<TKey, TValue> MakeKeyOrderDictionary<TKey, TValue>(IEnumerable<KeyValuePair<TKey, TValue>> items, Func<KeyValuePair<TKey, TValue>, int> orderFunc)
        {
            List<KeyValuePair<TKey, TValue>> itemList = new List<KeyValuePair<TKey, TValue>>(items);
            itemList.Sort((x, y) => orderFunc(x).CompareTo(orderFunc(y)));

            Dictionary<TKey, TValue> resultDict = new Dictionary<TKey, TValue>();
            foreach (var item in itemList)
            {
                resultDict[item.Key] = item.Value;
            }

            return resultDict;
        }
        protected override IList<int> GetSupportedGroups(IList<int> namedGroupRoles)
        {
            return SupportedGroups;
        }
        //protected override int[] GetSupportedCipherSuites()
        //{
        //    //return TlsUtilities.GetSupportedCipherSuites(Crypto, DefaultCipherSuites);
        //    var supportedGroups = new ArrayList();
        //    TlsUtilities.AddIfSupported(supportedGroups, Crypto, SupportedGroups);
        //    return supportedGroups;
        //}
        //protected override IList GetSupportedGroups(IList namedGroupRoles)
        //{
        //    var supportedGroups = new ArrayList();
        //    TlsUtilities.AddIfSupported(supportedGroups, Crypto, SupportedGroups);
        //    return supportedGroups;
        //}

        protected override ProtocolVersion[] GetSupportedVersions() => SupportedVersions;
        protected override IList<SignatureAndHashAlgorithm> GetSupportedSignatureAlgorithms() => SignatureAlgorithms;
        protected override int[] GetSupportedCipherSuites() => SupportedCiphers;
        protected override IList<ServerName> GetSniServerNames() => _serverNames;

        private static SignatureAndHashAlgorithm CreateSignatureAlgorithm(int signatureScheme)
        {
            short hashAlgorithm = SignatureScheme.GetHashAlgorithm(signatureScheme);
            short signatureAlgorithm = SignatureScheme.GetSignatureAlgorithm(signatureScheme);
            return new SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm);
        }

        public class Ja3TlsAuthentication : TlsAuthentication
        {

            private readonly TlsContext m_context;
            public Ja3TlsAuthentication(TlsContext context)
            {
                this.m_context = context;
            }

            public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest)
            {
                return null;
            }
            public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {

            }
        }

    }

}
