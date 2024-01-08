using Org.BouncyCastle.Tls;
using System;
using System.Collections.Generic;
using System.Text;

namespace JA3
{
    internal class Ja3TlsAuthentication : TlsAuthentication
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
