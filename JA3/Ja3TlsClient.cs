using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;

namespace JA3
{
    internal class Ja3TlsClient : DefaultTlsClient
    {

        internal TlsSession m_session;
        private ServerName[] _serverNames;



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


        internal Ja3TlsClient(TlsSession session)
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
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        };


        public int[] SupportedGroups { get; set; } = new[] {
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

        public ProtocolVersion[] SupportedVersions { get; set; } = ProtocolVersion.TLSv13.DownTo(ProtocolVersion.TLSv10);


        public override void NotifyServerVersion(ProtocolVersion serverVersion)
        {
            base.NotifyServerVersion(serverVersion);
            //Console.WriteLine("TLS client negotiated " + serverVersion);
        }

        public override IList GetExternalPsks()
        {
            byte[] identity = Strings.ToUtf8ByteArray("client");
            TlsSecret key = Crypto.CreateSecret(Strings.ToUtf8ByteArray("TLS_TEST_PSK"));
            int prfAlgorithm = PrfAlgorithm.tls13_hkdf_sha256;
            return TlsUtilities.VectorOfOne(new BasicTlsPskExternal(identity, key, prfAlgorithm));
        }

        //扩展
        public override IDictionary GetClientExtensions()
        {
            IDictionary clientExtensions = TlsExtensionsUtilities.EnsureExtensionsInitialised(base.GetClientExtensions());

            TlsExtensionsUtilities.AddMaxFragmentLengthExtension(clientExtensions, MaxFragmentLength.pow2_9);
            TlsExtensionsUtilities.AddPaddingExtension(clientExtensions, m_context.Crypto.SecureRandom.Next(16));
            TlsExtensionsUtilities.AddTruncatedHmacExtension(clientExtensions);
            TlsExtensionsUtilities.AddRecordSizeLimitExtension(clientExtensions, 16385);
            TlsExtensionsUtilities.AddPaddingExtension(clientExtensions, 0);

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
            return clientExtensions;
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


        protected override IList GetSupportedGroups(IList namedGroupRoles)
        {
            var supportedGroups = new ArrayList();
            TlsUtilities.AddIfSupported(supportedGroups, Crypto, SupportedGroups);
            return supportedGroups;
        }

        protected override ProtocolVersion[] GetSupportedVersions() => SupportedVersions;
        protected override IList GetSupportedSignatureAlgorithms() => (IList)SignatureAlgorithms;
        protected override int[] GetSupportedCipherSuites() => SupportedCiphers;
        protected override IList GetSniServerNames() => _serverNames;

        private static SignatureAndHashAlgorithm CreateSignatureAlgorithm(int signatureScheme)
        {
            short hashAlgorithm = SignatureScheme.GetHashAlgorithm(signatureScheme);
            short signatureAlgorithm = SignatureScheme.GetSignatureAlgorithm(signatureScheme);
            return new SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm);
        }


    }


}
