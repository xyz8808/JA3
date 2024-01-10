using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using HttpTwo.Internal;
using JA3Test;
using Org.BouncyCastle.Tls;

namespace HttpTwo
{
    public class Http2ConnectionSettings
    {
        public Http2ConnectionSettings(string url, WebProxy proxy = null, X509CertificateCollection certificates = null)
            : this(new Uri(url), proxy, certificates)
        {
        }

        public Http2ConnectionSettings(Uri uri, WebProxy proxy = null, X509CertificateCollection certificates = null)
            : this(uri.Host, (uint)uri.Port, uri.Scheme == Uri.UriSchemeHttps,proxy, certificates)
        {
        }

        public Http2ConnectionSettings(string host, uint port = 80, bool useTls = false, WebProxy proxy=null, X509CertificateCollection certificates = null)
        {
            Host = host;
            Port = port;
            UseTls = useTls;
            Certificates = certificates;
            Proxy = proxy;
        }
        public WebProxy Proxy { get; set; }
        public string Host { get; private set; }
        public uint Port { get; private set; }
        public bool UseTls { get; private set; }
        public X509CertificateCollection Certificates { get; private set; }

        public TimeSpan ConnectionTimeout { get; set; } = TimeSpan.FromSeconds(60);
        public bool DisablePushPromise { get; set; } = false;
    }

    public class Http2Connection
    {
        public const string ConnectionPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

        static Http2Connection()
        {
            ServicePointManager.ServerCertificateValidationCallback +=
                (sender, certificate, chain, sslPolicyErrors) => true;
        }

        public Http2Connection(Http2ConnectionSettings connectionSettings, IStreamManager streamManager, IFlowControlManager flowControlManager)
        {
            this.flowControlManager = flowControlManager;
            this.streamManager = streamManager;

            ConnectionSettings = connectionSettings;
            Settings = new Http2Settings();
            Settings.MaxConcurrentStreams = 100;
            Settings.HeaderTableSize = 65535;
            Settings.InitialWindowSize = 6291456;
            Settings.MaxHeaderListSize = 262144;
            Settings.MaxFrameSize = 16384;
            Settings.EnablePush = false;
            queue = new FrameQueue(flowControlManager);
        }

        public Http2Settings Settings { get; private set; }
        public Http2ConnectionSettings ConnectionSettings { get; private set; }

        IFlowControlManager flowControlManager;
        readonly IStreamManager streamManager;
        readonly FrameQueue queue;

        TcpClient tcp;
        Stream clientStream;
        SslStream sslStream;
        CancellationToken cancellationToken = new CancellationToken();
        long receivedDataCount = 0;
        public uint ReceivedDataCount => (uint)Interlocked.Read(ref receivedDataCount);
        async Task<Stream> ConnectToProxy()
        {
            tcp = new TcpClient();
            var Timeout = 10 * 1000;
            tcp.ReceiveTimeout = 10*1000;
            tcp.SendTimeout = 10 * 1000;
        
            if (ConnectionSettings.Proxy == null)
            {
                await tcp.ConnectAsync(ConnectionSettings.Host, (int)ConnectionSettings.Port, cancellationToken);
                return tcp.GetStream();
            }
            else
            {
                //client = new TcpClient(proxy.Address.Host, proxy.Address.Port);
                await tcp.ConnectAsync(ConnectionSettings.Proxy.Address.Host, ConnectionSettings.Proxy.Address.Port, cancellationToken);

                var data = $"CONNECT {"tls.browserleaks.com"}:{443} HTTP/1.1\r\n" +
                    //$"User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko\r\n" +
                    $"Host: {"tls.browserleaks.com"}\r\n" +
                    $"Content-Length: 0\r\n" +
                    $"DNT: 1\r\n";
                if (ConnectionSettings.Proxy.Credentials != null)
                {
                    //var ca = ConnectionSettings.Proxy.Credentials.GetCredential(uri, "Basic");
                    //data += $"Proxy-Authorization: Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{ca.UserName}:{ca.Password})"))}\r\n";
                }
                //data += $"Connection: Keep-Alive\r\n" +
                //    $"Pragma: no-cache\r\n\r\n";
                data += "\r\n";
                var stream = tcp.GetStream();
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
            if (contentLength == 0 && body_buff == null)
            {
                resp.Content = new ByteArrayContent(new byte[0]);
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
                while (await sslStream.ReadAsync(tmp_buff, 0, tmp_buff.Length, cancellationToken) != tmp_buff.Length) ;
                len_buff.AddRange(tmp_buff);
                if (len_buff.Count >= 3 && len_buff.Last() == 10 && len_buff[len_buff.Count - 2] == 13)//len½áÊø 
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
                if (name == "Content-Type" || name == "Content-Encoding" || name == "Expires" || name == "Last-Modified")
                {
                    continue;
                }
                resp.Headers.Add(h.Groups["key"].Value.Trim(), h.Groups["value"].Value.Trim());
            }
            await ReadBody(header, resp, sslStream);
            return resp;
        }
        public async Task Connect()
        {
            if (IsConnected())
                return;

            //tcp = new TcpClient
            //{
            //    // Disable Nagle for HTTP/2
            //    NoDelay = true
            //};

            //await tcp.ConnectAsync(ConnectionSettings.Host, (int)ConnectionSettings.Port).ConfigureAwait(false);
            var stream =await ConnectToProxy();
            if (ConnectionSettings.UseTls)
            {
                
                    var cl = new Ja3TlsClient(null);
                cl.EnableHttp2 = true;
                    cl.ServerNames = new[] { "tls.browserleaks.com" };
                    var protocol = new TlsClientProtocol(stream);
                    protocol.Connect(cl);
                clientStream = protocol.Stream;
            }
            else
            {
                clientStream = tcp.GetStream();
            }

            // Ensure we have a size for the stream '0'
            flowControlManager.GetWindowSize(0);

            // Send out preface data
            var prefaceData = System.Text.Encoding.ASCII.GetBytes(ConnectionPreface);
            await clientStream.WriteAsync (prefaceData, 0, prefaceData.Length).ConfigureAwait (false);
            await clientStream.FlushAsync ().ConfigureAwait (false);

            // Start reading the stream on another thread
            var readTask = Task.Factory.StartNew (() => {
                try { Read (); }
                catch (Exception ex) {
                    Log.Debug ("Read error: " + ex);
                    Disconnect ();
                }
            }, TaskCreationOptions.LongRunning);

            readTask.ContinueWith (t => {
                // TODO: Handle the error
                Disconnect ();
            }, TaskContinuationOptions.OnlyOnFaulted).Forget ();

            // Start a thread to handle writing queued frames to the stream
            var writeTask = Task.Factory.StartNew (Write, TaskCreationOptions.LongRunning);
            writeTask.ContinueWith (t => {
                // TODO: Handle the error
                Disconnect ();
            }, TaskContinuationOptions.OnlyOnFaulted).Forget ();

            // Send initial blank settings frame
            var s = new SettingsFrame()
            {
                 HeaderTableSize = 65536,
                 MaxConcurrentStreams= 1000,
                 InitialWindowSize= 6291456,
                 MaxHeaderListSize= 262144,
                 
            };
            if (ConnectionSettings.DisablePushPromise)
                s.EnablePush = false;

            await QueueFrame (s).ConfigureAwait (false);
        }

        public void Disconnect ()
        {
            // complete the blocking collection
            queue.Complete ();

            // We want to clean up the connection here so let's just try to close/dispose
            // everything

            // Analysis disable EmptyGeneralCatchClause
            try { clientStream.Close (); } catch { }
            try { clientStream.Dispose (); } catch { }

            if (ConnectionSettings.UseTls && sslStream != null) {
                try { sslStream.Close (); } catch { }
                try { sslStream.Dispose (); } catch { }
            }

            try { tcp.Client.Shutdown (SocketShutdown.Both); } catch { }
            try { tcp.Client.Dispose (); } catch { }

            try { tcp.Close (); } catch { }
            // Analysis restore EmptyGeneralCatchClause

            tcp = null;
            sslStream = null;
            clientStream = null;
        }

        bool IsConnected ()
        {
            if (tcp == null || clientStream == null || tcp.Client == null)
                return false;

            if (!tcp.Connected || !tcp.Client.Connected)
                return false;

            if (!tcp.Client.Poll (1000, SelectMode.SelectRead)
                || !tcp.Client.Poll (1000, SelectMode.SelectWrite))
                return false;

            return true;
        }

        readonly SemaphoreSlim lockWrite = new SemaphoreSlim (1);

        public async Task QueueFrame(IFrame frame) => await queue.Enqueue(frame).ConfigureAwait(false);

        public async Task FreeUpWindowSpace ()
        {
            var sizeToFree = Interlocked.Exchange (ref receivedDataCount, 0);

            if (sizeToFree <= 0)
                return;

            await QueueFrame (new WindowUpdateFrame {
                StreamIdentifier = 0,
                WindowSizeIncrement = (uint)sizeToFree
            }).ConfigureAwait (false);
        }

        readonly List<byte> buffer = new List<byte> ();

        async void Read()
        {
            int rx;
            var b = new byte[4096];

            while (true) {

                try {
                    rx = await clientStream.ReadAsync(b, 0, b.Length).ConfigureAwait (false);
                } catch {
                    rx = -1;
                }

                if (rx > 0) {
                    // Add all the bytes read into our buffer list
                    for (var i = 0; i < rx; i++)
                        buffer.Add (b [i]);

                    while (true)
                    {
                        // We need at least 9 bytes to process the frame
                        // 9 octets is the frame header length
                        if (buffer.Count < 9)
                            break;

                        // Find out the frame length
                        // which is a 24 bit uint, so we need to convert this as c# uint is 32 bit
                        var flen = new byte[4];
                        flen [0] = 0x0;
                        flen [1] = buffer.ElementAt (0);
                        flen [2] = buffer.ElementAt (1);
                        flen [3] = buffer.ElementAt (2);

                        var frameLength = BitConverter.ToUInt32 (flen.EnsureBigEndian (), 0);

                        // If we are expecting a payload that's bigger than what's in our buffer
                        // we should keep reading from the stream
                        if (buffer.Count - 9 < frameLength)
                            break;

                        // If we made it this far, the buffer has all the data we need, let's get it out to process
                        var data = buffer.GetRange (0, (int)frameLength + 9).ToArray ();
                        // remove the processed info from the buffer
                        buffer.RemoveRange (0, (int)frameLength + 9);

                        // Get the Frame Type so we can instantiate the right subclass
                        var frameType = data [3]; // 4th byte in frame header is TYPE

                        // we need to turn the stream id into a uint
                        var frameStreamIdData = new byte[4];
                        Array.Copy (data, 5, frameStreamIdData, 0, 4);
                        var frameStreamId = Util.ConvertFromUInt31 (frameStreamIdData.EnsureBigEndian ());

                        // Create a new typed instance of our abstract Frame
                        var frame = Frame.Create ((FrameType)frameType);

                        try {
                            // Call the specific subclass implementation to parse
                            frame.Parse (data);
                        } catch (Exception ex) {
                            Log.Error ("Parsing Frame Failed: {0}", ex);
                            throw ex;
                        }

                        Log.Debug ("<- {0}", frame);

                        // If it's a settings frame, we should note the values and
                        // return the frame with the Ack flag set
                        if (frame.Type == FrameType.Settings) {

                            var settingsFrame = frame as SettingsFrame;

                            // Update our instance of settings with the new data
                            Settings.UpdateFromFrame (settingsFrame, flowControlManager);

                            // See if this was an ack, if not, return an empty
                            // ack'd settings frame
                            if (!settingsFrame.Ack)
                                await QueueFrame (new SettingsFrame { Ack = true }).ConfigureAwait (false);

                        } else if (frame.Type == FrameType.Ping) {

                            var pingFrame = frame as PingFrame;
                            // See if we need to respond to the ping request (if it's not-ack'd)
                            if (!pingFrame.Ack) {
                                // Ack and respond
                                pingFrame.Ack = true;
                                await QueueFrame (pingFrame).ConfigureAwait (false);
                            }

                        } else if (frame.Type == FrameType.Data) {

                            // Increment our received data counter
                            Interlocked.Add (ref receivedDataCount, frame.PayloadLength);
                        }

                        // Some other frame type, just pass it along to the stream
                        var stream = await streamManager.Get(frameStreamId).ConfigureAwait (false);
                        stream.ProcessReceivedFrames(frame);
                    }

                } else {
                    // Stream was closed, break out of reading loop
                    break;
                }
            }

            // Cleanup
            Disconnect();
        }

        async Task Write ()
        {
            foreach (var frame in queue.GetConsumingEnumerable ()) {
                if (frame == null) {
                    Log.Info ("Null frame dequeued");
                    continue;
                }

                Log.Debug ("-> {0}", frame);

                var data = frame.ToBytes ().ToArray ();

                await lockWrite.WaitAsync ().ConfigureAwait (false);

                try {
                    await clientStream.WriteAsync(data, 0, data.Length).ConfigureAwait (false);
                    await clientStream.FlushAsync().ConfigureAwait (false);
                    var stream = await streamManager.Get (frame.StreamIdentifier).ConfigureAwait (false);
                    stream.ProcessSentFrame (frame);
                } catch (Exception ex) {
                    Log.Warn ("Error writing frame: {0}, {1}", frame.StreamIdentifier, ex);
                } finally {
                    lockWrite.Release();
                }
            }
        }
    }
}
