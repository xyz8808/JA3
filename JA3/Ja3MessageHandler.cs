using JA3Test;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Tls;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace JA3
{
    public class Ja3MessageHandler : HttpMessageHandler
    {
        public CookieContainer CookieContainer { get; set; } = new CookieContainer();
        public bool UseCookies { get; set; } = true;

        public bool AllowAutoRedirect { get; set; } = true;
        public WebProxy proxy { get; set; }

        bool inited = false;
        TcpClient client;
        Ja3TlsClient cl = new Ja3TlsClient(null);
        Stream stream;
        Uri uri { get; set; }
        public int Timeout { get; set; } = 10 * 1000;
        CancellationToken cancellationToken;
        async Task Init()
        {

            cl.ServerNames = new[] { uri.Host };
            var s = await ConnectToProxy();
            if (uri.Scheme == "https")
            {
                var protocol = new TlsClientProtocol(s);
                protocol.Connect(cl);

                //Console.WriteLine("SSL Handshake Success.");
                stream = protocol.Stream;
            }
            else
            {
                stream = s;
            }
            inited = true;
        }
        async Task<Stream> ConnectToProxy()
        {
            client = new TcpClient();
            client.ReceiveTimeout = Timeout;
            client.SendTimeout = Timeout;
            if (proxy == null)
            {
                await client.ConnectAsync(uri.Host, uri.Port,cancellationToken);
                return client.GetStream();
            }
            else
            {
                //client = new TcpClient(proxy.Address.Host, proxy.Address.Port);
                await client.ConnectAsync(proxy.Address.Host, proxy.Address.Port, cancellationToken);

                var data = $"CONNECT {uri.Host}:{uri.Port} HTTP/1.1\r\n" +
                    //$"User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko\r\n" +
                    $"Host: {uri.Host}\r\n" +
                    $"Content-Length: 0\r\n" +
                    $"DNT: 1\r\n";
                if (proxy.Credentials != null)
                {
                    var ca = proxy.Credentials.GetCredential(uri, "Basic");
                    data += $"Proxy-Authorization: Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{ca.UserName}:{ca.Password})"))}\r\n";
                }
                //data += $"Connection: Keep-Alive\r\n" +
                //    $"Pragma: no-cache\r\n\r\n";
                data += "\r\n";
                var stream = client.GetStream();
                stream.ReadTimeout = Timeout;
                stream.WriteTimeout = Timeout;
                var buff = Encoding.UTF8.GetBytes(data);
                await stream.WriteAsync(buff, 0, buff.Length, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                var resp = await ReadHeader(stream);
                //Console.WriteLine(resp);
                //Console.WriteLine(Encoding.UTF8.GetString(body));
                //Console.WriteLine("ConnectToProxy Success.");
                return stream;
            }
        }
        void SetCookie(HttpResponseMessage resp)
        {
            if(!UseCookies) { return; }
            if (resp.Headers.TryGetValues("Set-Cookie", out var cookieValueList))
            {
                foreach (var value in cookieValueList)
                {
                    CookieContainer.SetCookies(uri, value);
                }
            }
            //var ms = Regex.Matches(resp, "Set-Cookie:(?<name>[^=]+)=(?<value>[^;]+).*$", RegexOptions.Multiline);
            //foreach (Match item in ms)
            //{
            //    //var key = item.Groups["name"].Value.Trim();
            //    //var value = item.Groups["value"].Value.Trim();
            //    CookieContainer.SetCookies(uri, item.Value.Replace("");
            //}
        }
        async Task ReadBody(string header, HttpResponseMessage resp, Stream sslStream)
        {
            byte[] body_buff = null;
            var ContentEncoding = Regex.Match(header, "Content-Encoding:(?<value>.+)").Groups["value"].Value.Trim();
            var ContentType = Regex.Match(header, "Content-Type:(?<value>.+)").Groups["value"].Value.Trim();
            var TransferEncoding = Regex.Match(header, "Transfer-Encoding:(?<value>.+)").Groups["value"].Value.Trim();
            var contentLength = 0;
            var t = Regex.Match(header, "Content-Length:(?<value>.+)").Groups["value"].Value.Trim();
            if (!string.IsNullOrEmpty(t))
                contentLength = Convert.ToInt32(t);
            if (TransferEncoding == "chunked")
            {
                body_buff = await ReadChunkedData(sslStream);
            }
            if (contentLength == 0&& body_buff==null )
            {
                resp.Content=new ByteArrayContent(new byte[0]);
                return;
            }
            else if (contentLength > 0)
            {
                int bytes = 0;
                byte[] buffer = new byte[2048];
                body_buff = new byte[contentLength];
                for (int i = 0; i < contentLength;)
                {
                    bytes = await sslStream.ReadAsync(body_buff, i, Math.Min(buffer.Length, body_buff.Length - i), cancellationToken);
                    i += bytes;
                }
            }
            



            if (!string.IsNullOrEmpty(ContentEncoding))
            {
                using (var ms = new MemoryStream(body_buff))
                {
                    Stream decompressStream = ms;
                    using (var outputStream = new MemoryStream())
                    {
                        if (ContentEncoding.ToLower().Contains("gzip"))
                            decompressStream = new GZipStream(ms, CompressionMode.Decompress);
                        else if (ContentEncoding.ToLower().Contains("deflate"))
                            decompressStream = new DeflateStream(ms, CompressionMode.Decompress);
                        else if (ContentEncoding.ToLower().Contains("br"))
                            decompressStream = new BrotliStream(ms, CompressionMode.Decompress);
                        decompressStream.CopyTo(outputStream);
                        body_buff = outputStream.ToArray();
                    }
                }
            }
            resp.Content = new ByteArrayContent(body_buff);
            resp.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(ContentType.Split(";")[0]);
            if (!string.IsNullOrEmpty(ContentEncoding))
                resp.Content.Headers.ContentEncoding.Add(ContentEncoding);
        }
        async Task<byte[]> ReadChunkedData(Stream sslStream)
        {
            var tmp_buff = new byte[1];
            var resp_buff = new List<byte>();
            var len_buff = new List<byte>();
            while (true)
            {
                while ( await sslStream.ReadAsync(tmp_buff, 0, tmp_buff.Length, cancellationToken)!=tmp_buff.Length);
                len_buff.AddRange(tmp_buff);
                if (len_buff.Count >= 3 && len_buff.Last() == 10 && len_buff[len_buff.Count - 2] == 13)//len结束 
                {
                    var len_str = Encoding.ASCII.GetString(len_buff.ToArray(), 0, len_buff.Count - 2);
                    var len = Convert.ToInt32(len_str, 16);
                    if (len == 0)
                    {
                        while (await sslStream.ReadAsync(tmp_buff, 0, tmp_buff.Length, cancellationToken) != tmp_buff.Length) ;
                        while (await sslStream.ReadAsync(tmp_buff, 0, tmp_buff.Length, cancellationToken) != tmp_buff.Length) ;
                        break;
                    }
                    var data_buff = new byte[len];
                    var read_data_count = 0;
                    while (read_data_count < data_buff.Length)
                    {
                        read_data_count += await sslStream.ReadAsync(data_buff, read_data_count, data_buff.Length - read_data_count, cancellationToken);
                    }
                    resp_buff.AddRange(data_buff);
                    while (await sslStream.ReadAsync(tmp_buff, 0, tmp_buff.Length, cancellationToken) != tmp_buff.Length) ;
                    while (await sslStream.ReadAsync(tmp_buff, 0, tmp_buff.Length, cancellationToken) != tmp_buff.Length) ;
                    len_buff.Clear();
                }
            }
            return resp_buff.ToArray();
        }
        async Task<HttpResponseMessage> ReadHeader(Stream sslStream)
        {
            var header_buff = new List<byte>();
            var tmp_buff = new byte[1];

            while (true)
            {
                while (await sslStream.ReadAsync(tmp_buff, 0, tmp_buff.Length, cancellationToken) != tmp_buff.Length) ;
                header_buff.AddRange(tmp_buff);
                //var tmp = Encoding.UTF8.GetString(header_buff.ToArray());
                if (header_buff.Count > 4 && tmp_buff[0] == 10 && header_buff[header_buff.Count - 2] == 13 && header_buff[header_buff.Count - 3] == 10 && header_buff[header_buff.Count - 4] == 13)
                {
                    break;
                }
            }
            var header = Encoding.UTF8.GetString(header_buff.ToArray());
            var header_lines = header.Split("\r\n".ToCharArray(), int.MaxValue, StringSplitOptions.RemoveEmptyEntries);
            if (header_lines.Length <= 0 || header_lines[0].Split(' ').Length < 2)
            {
                Console.WriteLine($"header is empty request:{uri}\r\nheader:{header}");
                return null;
            }
            else
            {
                //Console.WriteLine($"header  :{header}");
            }


            var resp = new HttpResponseMessage((HttpStatusCode)Convert.ToInt32(header_lines[0].Split(' ')[1]));



            foreach (var h_line in header_lines.Skip(1))
            {
                var h = Regex.Match(h_line, "(?<key>[^:]+):(?<value>.*)");
                if (!h.Success) { continue; }
                var name = h.Groups["key"].Value;
                if (name == "Content-Length")
                {
                    continue;
                    var len = Convert.ToInt32(h.Groups["value"].Value);
                    resp.Content = new ByteArrayContent(new byte[len]);

                }
                if (name == "Content-Type"|| name == "Content-Encoding"||name== "Expires"||name== "Last-Modified")
                {
                    continue;
                }
                resp.Headers.Add(h.Groups["key"].Value.Trim(), h.Groups["value"].Value.Trim());
            }
            SetCookie(resp);
            await ReadBody(header, resp, stream);
            return resp;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            this.cancellationToken=cancellationToken;
            if (uri!=null && (request.RequestUri.Scheme != uri.Scheme||request.RequestUri.Host!=uri.Host))
                inited = false;
            uri = request.RequestUri;
            if (!inited)
                await Init();

            //stream.ReadTimeout = Timeout;
            //stream.WriteTimeout = Timeout;
            var http_p = new StringBuilder();
            http_p.AppendLine($"{request.Method} {uri.PathAndQuery} HTTP/1.1");
            http_p.AppendLine($"Host: {uri.Host}");
            if (UseCookies)
            {
                var cookies=CookieContainer.GetCookies(uri);
                var cookie_str = string.Join(';', cookies.Select(o => $" {o.Name}={o.Value}"));
                http_p.AppendLine($"Cookie: {cookie_str}");
            }
            //http_p.AppendLine($"Cookie: {string.Join(';', cookies.Select(o => $" {o.Key}={o.Value}"))}");
            foreach (var item in request.Headers)
            {
                http_p.AppendLine($"{item.Key}: {string.Join(" ", item.Value)}");
            }

            byte[] body_buff = null;
            if (request.Content != null)
            {
                body_buff = await request.Content.ReadAsByteArrayAsync();
                http_p.AppendLine($"Content-Length: {body_buff.Length}");
                http_p.AppendLine($"Content-Type: {request.Content.Headers.ContentType}");
            }
            http_p.AppendLine($"");

            var http_str = http_p.ToString();
            var h_buff = Encoding.UTF8.GetBytes(http_str);
            await stream.WriteAsync(h_buff, 0, h_buff.Length, cancellationToken);
            await stream.FlushAsync(cancellationToken);
            if (request.Content != null)
            {
                await stream.WriteAsync(body_buff, 0, body_buff.Length, cancellationToken);
                await stream.FlushAsync(cancellationToken);
            }
            // Read message from the server.
            var resp = await ReadHeader(stream);
            resp.RequestMessage = request;

         
        


            /*
             * 
             * 
             *HTTP/1.1 302 Found
Cache-Control: private
Content-Length: 137
Content-Type: text/html; charset=utf-8
Location: https://cn.bing.com/
             */
            if (AllowAutoRedirect && (resp.StatusCode == HttpStatusCode.Found || resp.StatusCode == HttpStatusCode.Moved))
            {
                var location = resp.Headers.Location;
                request.RequestUri = location;
                return await SendAsync(request, cancellationToken);
            }
            return resp;

        }

        protected override void Dispose(bool disposing)
        {
            try
            {
                stream?.Close();
            }
            catch { }
            try
            {
                client?.Close();
            }
            catch { }
        }

    }
}
