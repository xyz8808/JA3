using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using HttpTwo.Internal;

namespace HttpTwo
{
    public class Http2Client
    {
        readonly Http2Connection connection;

        public Http2Client (Uri uri, X509CertificateCollection certificates = null, IStreamManager streamManager = null, IFlowControlManager flowControlManager = null)
            : this (new Http2ConnectionSettings (uri, certificates: certificates), streamManager, flowControlManager)
        {
        }

        //public Http2Client (string url, X509CertificateCollection certificates = null, IStreamManager streamManager = null, IFlowControlManager flowControlManager = null)
        //    : this (new Http2ConnectionSettings (url,certificates: certificates), streamManager, flowControlManager)
        //{
        //}

        public Http2Client (Http2ConnectionSettings connectionSettings, IStreamManager streamManager = null, IFlowControlManager flowControlManager = null)
        {
            FlowControlManager = flowControlManager ?? new FlowControlManager ();
            StreamManager = streamManager ?? new StreamManager (this.FlowControlManager);
            ConnectionSettings = connectionSettings;

            connection = new Http2Connection (ConnectionSettings, this.StreamManager, this.FlowControlManager);
        }

        public Http2ConnectionSettings ConnectionSettings { get; private set; }
        public IStreamManager StreamManager { get; }
        public IFlowControlManager FlowControlManager { get; }

        public async Task Connect() => await connection.Connect().ConfigureAwait(false);

        public async Task<Http2Response> Post(Uri uri, NameValueCollection headers = null, byte[] data = null) => await Send(uri, HttpMethod.Post, headers, data).ConfigureAwait(false);
        public async Task<Http2Response> Post(Uri uri, NameValueCollection headers = null, Stream data = null) => await Send(uri, HttpMethod.Post, headers, data).ConfigureAwait(false);

        public async Task<Http2Response> Send(Uri uri, HttpMethod method, NameValueCollection headers = null, Stream data = null) => await Send(new CancellationToken(), uri, method, headers, data).ConfigureAwait(false);

        public async Task<Http2Response> Send (Uri uri, HttpMethod method, NameValueCollection headers = null, byte[] data = null)
        {
            MemoryStream ms = null;

            if (data != null)
                ms = new MemoryStream (data);

            return await Send (new CancellationToken (), uri, method, headers, ms).ConfigureAwait (false);
        }

        public async Task<Http2Response> Send (CancellationToken cancelToken, Uri uri, HttpMethod method, NameValueCollection headers = null, Stream data = null)
        {
            var semaphoreClose = new SemaphoreSlim(0);

            await connection.Connect ().ConfigureAwait (false);

            var stream = await StreamManager.Get ().ConfigureAwait (false);
            stream.OnFrameReceived += async (frame) =>
            {
                // Check for an end of stream state
                if (stream.State == StreamState.HalfClosedRemote || stream.State == StreamState.Closed)
                    semaphoreClose.Release ();
            };

            var sentEndOfStream = false;

            var allHeaders = new NameValueCollection ();
            allHeaders.Add (":method", method.Method.ToUpperInvariant ());
            allHeaders.Add(":authority", uri.Authority);
            allHeaders.Add(":scheme", uri.Scheme);
            allHeaders.Add (":path", uri.PathAndQuery);
            if (headers != null && headers.Count > 0)
                allHeaders.Add (headers);

            var headerData = Util.PackHeaders (allHeaders, connection.Settings.HeaderTableSize);

            var numFrames = (int)Math.Ceiling ((double)headerData.Length / (double)connection.Settings.MaxFrameSize);

            for (var i = 0; i < numFrames; i++) {
                // First item is headers frame, others are continuation
                var frame = (i == 0) ?
                    (IFrameContainsHeaders)new HeadersFrame (stream.StreamIdentifer)
                    : (IFrameContainsHeaders)new ContinuationFrame (stream.StreamIdentifer);

                // Set end flag if this is the last item
                if (i == numFrames - 1)
                    frame.EndHeaders = true;

                var maxFrameSize = connection.Settings.MaxFrameSize;

                var amt = maxFrameSize;
                if ( i * maxFrameSize + amt > headerData.Length)
                    amt = (uint)headerData.Length - (uint)(i * maxFrameSize);
                frame.HeaderBlockFragment = new byte[amt];
                Array.Copy (headerData, i * maxFrameSize, frame.HeaderBlockFragment, 0, amt);

                // If we won't s end
                if (data == null && frame is HeadersFrame) {
                    sentEndOfStream = true;
                    (frame as HeadersFrame).EndStream = true;
                }

                await connection.QueueFrame (frame).ConfigureAwait (false);
            }

            if (data != null) {
                var supportsPosLength = true; // Keep track of if we threw exceptions trying pos/len of stream

                // Break stream up into data frames within allowed size
                var dataFrameBuffer = new byte[connection.Settings.MaxFrameSize];
                while (true) {

                    var rd = await data.ReadAsync (dataFrameBuffer, 0, dataFrameBuffer.Length).ConfigureAwait (false);

                    if (rd <= 0)
                        break;

                    // Make a new data frame with a buffer the size we read
                    var dataFrame = new DataFrame(stream.StreamIdentifer) {
                        Data = new byte[rd]
                    };

                    // Copy over the data we read
                    Array.Copy(dataFrameBuffer, 0, dataFrame.Data, 0, rd);

                    try {
                        // See if the stream supports Length / Position to try and detect EOS
                        // we also want to see if we previously had an exception trying this
                        // and not try again if we did, since throwing exceptions every single
                        // read operation is wasteful
                        if (supportsPosLength && data.Position >= data.Length) {
                            dataFrame.EndStream = true;
                            sentEndOfStream = true;
                        }
                    } catch {
                        supportsPosLength = false;
                        sentEndOfStream = false;
                    }

                    await connection.QueueFrame (dataFrame).ConfigureAwait (false);
                }
            }

            // Send an empty frame with end of stream flag
            if (!sentEndOfStream)
                await connection.QueueFrame(new DataFrame(stream.StreamIdentifer) { EndStream = true }).ConfigureAwait(false);

            if (!await semaphoreClose.WaitAsync (ConnectionSettings.ConnectionTimeout, cancelToken).ConfigureAwait (false))
                throw new TimeoutException ();

            var responseData = new List<byte> ();
            var rxHeaderData = new List<byte> ();

            foreach (var f in stream.ReceivedFrames) {
                if (f.Type == FrameType.Headers || f.Type == FrameType.Continuation) {
                    // Get the header data and add it to our buffer
                    var fch = (IFrameContainsHeaders)f;
                    if (fch.HeaderBlockFragment != null && fch.HeaderBlockFragment.Length > 0)
                        rxHeaderData.AddRange (fch.HeaderBlockFragment);
                } else if (f.Type == FrameType.PushPromise) {
                    // TODO: In the future we need to implement PushPromise beyond grabbing header data
                    var fch = (IFrameContainsHeaders)f;
                    if (fch.HeaderBlockFragment != null && fch.HeaderBlockFragment.Length > 0)
                        rxHeaderData.AddRange (fch.HeaderBlockFragment);
                } else if (f.Type == FrameType.Data) {
                    responseData.AddRange ((f as DataFrame).Data);
                } else if (f.Type == FrameType.GoAway) {
                    if (f is GoAwayFrame fga && fga.AdditionalDebugData != null && fga.AdditionalDebugData.Length > 0)
                        responseData.AddRange(fga.AdditionalDebugData);
                }
            }

            var responseHeaders = Util.UnpackHeaders (rxHeaderData.ToArray (),
                connection.Settings.MaxHeaderListSize.HasValue ? (int)connection.Settings.MaxHeaderListSize.Value : 8192,
                (int)connection.Settings.HeaderTableSize);

            var strStatus = "500";
            if (responseHeaders [":status"] != null)
                strStatus = responseHeaders [":status"];

            var statusCode = HttpStatusCode.OK;
            Enum.TryParse<HttpStatusCode> (strStatus, out statusCode);

            // Remove the stream from being tracked since we're done with it
            await StreamManager.Cleanup (stream.StreamIdentifer).ConfigureAwait (false);

            // Send a WINDOW_UPDATE frame to release our stream's data count
            // TODO: Eventually need to do this on the stream itself too (if it's open)
            await connection.FreeUpWindowSpace ().ConfigureAwait (false);

            return new Http2Response {
                Status = statusCode,
                Stream = stream,
                Headers = responseHeaders,
                Body = responseData.ToArray ()
            };
        }

        public async Task<bool> Ping (byte[] opaqueData, CancellationToken cancelToken)
        {
            if (opaqueData == null || opaqueData.Length <= 0)
                throw new ArgumentNullException (nameof(opaqueData));

            await connection.Connect ().ConfigureAwait (false);

            var semaphoreWait = new SemaphoreSlim (0);
            var opaqueDataMatch = false;

            var connectionStream = await StreamManager.Get (0).ConfigureAwait (false);

            Http2Stream.FrameReceivedDelegate frameRxAction;
            frameRxAction = new Http2Stream.FrameReceivedDelegate (frame => {
                if (frame is PingFrame pf) {
                    opaqueDataMatch = pf.Ack && pf.OpaqueData != null && pf.OpaqueData.SequenceEqual(opaqueData);
                    semaphoreWait.Release();
                }
            });

            // Wire up the event to listen for ping response
            connectionStream.OnFrameReceived += frameRxAction;

            // Construct ping request
            var pingFrame = new PingFrame {
                OpaqueData = new byte[opaqueData.Length]
            };
            opaqueData.CopyTo (pingFrame.OpaqueData, 0);

            // Send ping
            await connection.QueueFrame (pingFrame).ConfigureAwait (false);

            // Wait for either a ping response or timeout
            await semaphoreWait.WaitAsync (cancelToken).ConfigureAwait (false);

            // Cleanup the event
            connectionStream.OnFrameReceived -= frameRxAction;

            return opaqueDataMatch;
        }

        public Task<bool> Disconnect() => Disconnect(Timeout.InfiniteTimeSpan);

        public async Task<bool> Disconnect (TimeSpan timeout)
        {
            var connectionStream = await StreamManager.Get (0).ConfigureAwait (false);

            var semaphoreWait = new SemaphoreSlim (0);
            var cancelTokenSource = new CancellationTokenSource ();
            var sentGoAway = false;

            var sentDelegate = new Http2Stream.FrameSentDelegate (frame => {
                if (frame.Type == FrameType.GoAway) {
                    sentGoAway = true;
                    semaphoreWait.Release ();
                }
            });

            connectionStream.OnFrameSent += sentDelegate;

            await connection.QueueFrame (new GoAwayFrame ()).ConfigureAwait (false);

            if (timeout != Timeout.InfiniteTimeSpan)
                cancelTokenSource.CancelAfter (timeout);

            await semaphoreWait.WaitAsync (cancelTokenSource.Token).ConfigureAwait (false);

            connectionStream.OnFrameSent -= sentDelegate;

            connection.Disconnect ();

            return sentGoAway;
        }

        public class Http2Response
        {
            public HttpStatusCode Status { get; set; }
            public Http2Stream Stream { get; set; }
            public NameValueCollection Headers { get;set; }
            public byte[] Body { get;set; }
        }
    }
}
