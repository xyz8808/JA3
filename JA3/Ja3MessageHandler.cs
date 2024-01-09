using JA3Test;
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
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace JA3
{
    public class Ja3MessageHandler : HttpMessageHandler
    {
        Dictionary<string, string> cookies = new Dictionary<string, string>();
        bool inited = false;
        TcpClient client;
        Ja3TlsClient cl = new Ja3TlsClient(null);
        Stream stream;
        Uri uri { get; set; }
        public WebProxy proxy { get; set; }
        public int Timeout { get; set; } = 10 * 1000;
        CancellationToken cancellationToken;
        async Task Init()
        {

            cl.ServerNames = new[] { uri.Host };
            var s = await ConnectToProxy();
            var protocol = new TlsClientProtocol(s);
            protocol.Connect(cl);

            //Console.WriteLine("SSL Handshake Success.");
            stream = protocol.Stream;

            inited = true;
        }
        async Task<Stream> ConnectToProxy()
        {
            client = new TcpClient();
            client.ReceiveTimeout = Timeout;
            client.SendTimeout = Timeout;
            if (proxy == null)
            {
                await client.ConnectAsync(uri.Host, 443,cancellationToken);
                return client.GetStream();
            }
            else
            {
                //client = new TcpClient(proxy.Address.Host, proxy.Address.Port);
                await client.ConnectAsync(proxy.Address.Host, proxy.Address.Port, cancellationToken);

                var data = $"CONNECT {uri.Host}:443 HTTP/1.1\r\n" +
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
                string resp = await ReadHeader(stream);
                var body = await ReadMessage(resp, stream);
                //Console.WriteLine(resp);
                //Console.WriteLine(Encoding.UTF8.GetString(body));
                //Console.WriteLine("ConnectToProxy Success.");
                return stream;
            }
        }
        void SetCookie(string resp)
        {
            var ms = Regex.Matches(resp, "Set-Cookie:(?<name>[^=]+)=(?<value>[^;]+)");
            foreach (Match item in ms)
            {
                var key = item.Groups["name"].Value.Trim();
                var value = item.Groups["value"].Value.Trim();
                if (cookies.ContainsKey(key))
                    cookies[key] = value;
                else
                    cookies.Add(key, value);
            }
        }
        async Task<byte[]> ReadMessage(string header, Stream sslStream)
        {

            var ContentEncoding = "";
            ContentEncoding = Regex.Match(header, "ContentEncoding:(?<value>.+)").Groups["value"].Value;
            var contentLength = 0;
            var t = Regex.Match(header, "Content-Length:(?<value>.+)").Groups["value"].Value;
            if (!string.IsNullOrEmpty(t))
                contentLength = Convert.ToInt32(t);
            if (contentLength == 0) return new byte[0];


            int bytes = 0;
            byte[] buffer = new byte[2048];
            var body_buff = new byte[contentLength];
            for (int i = 0; i < contentLength;)
            {
                bytes = await sslStream.ReadAsync(body_buff, i, Math.Min(buffer.Length, body_buff.Length - i), cancellationToken);
                i += bytes;
            }
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
                    return outputStream.ToArray();
                }
            }
        }
        async Task<string> ReadHeader(Stream sslStream)
        {
            var header_buff = new List<byte>();
            var tmp_buff = new byte[1];

            while (true)
            {
                var count = await sslStream.ReadAsync(tmp_buff, 0, tmp_buff.Length, cancellationToken);
                header_buff.AddRange(tmp_buff.Take(count));
                //var tmp = Encoding.UTF8.GetString(header_buff.ToArray());
                if (header_buff.Count > 4 && tmp_buff[0] == 10 && header_buff[header_buff.Count - 2] == 13 && header_buff[header_buff.Count - 3] == 10 && header_buff[header_buff.Count - 4] == 13)
                {
                    break;
                }
            }
            return Encoding.UTF8.GetString(header_buff.ToArray());
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            this.cancellationToken=cancellationToken;
            uri = request.RequestUri;
            if (!inited)
                await Init();

            //stream.ReadTimeout = Timeout;
            //stream.WriteTimeout = Timeout;
            var http_p = new StringBuilder();
            http_p.AppendLine($"{request.Method} {uri.PathAndQuery} HTTP/1.1");
            http_p.AppendLine($"Host: {uri.Host}");
            http_p.AppendLine($"Cookie: {string.Join(';', cookies.Select(o => $" {o.Key}={o.Value}"))}");
            foreach (var item in request.Headers)
            {
                http_p.AppendLine($"{item.Key}: {item.Value.First()}");
            }

            byte[] body_buff = null;
            if (request.Content != null)
            {
                body_buff = await request.Content.ReadAsByteArrayAsync();
                http_p.AppendLine($"Content-Length: {body_buff.Length}");
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
            string header = await ReadHeader(stream);
            SetCookie(header);
            var header_lines = header.Split("\r\n".ToCharArray(), int.MaxValue, StringSplitOptions.RemoveEmptyEntries);
            if (header_lines.Length <= 0 || header_lines[0].Split(' ').Length < 2)
            {
                Console.WriteLine($"header is empty request:{request.RequestUri} {request.Method}\r\nheader:{header}");
                return null;
            }
            else
            {
                //Console.WriteLine($"header  :{header}");
            }


            var httpResponseMsg = new HttpResponseMessage((HttpStatusCode)Convert.ToInt32(header_lines[0].Split(' ')[1]));



            foreach (var h_line in header_lines.Skip(1))
            {
                var h = Regex.Match(h_line, "(?<key>[^:]+):(?<value>.*)");
                httpResponseMsg.Headers.TryAddWithoutValidation(h.Groups["key"].Value.Trim(), h.Groups["value"].Value.Trim());
            }
            var resp = await ReadMessage(header, stream);

            if (resp != null && resp.Length > 0)
                httpResponseMsg.Content = new ByteArrayContent(resp);

            return httpResponseMsg;

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
