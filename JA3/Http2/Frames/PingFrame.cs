using System;
using System.Collections.Generic;

namespace HttpTwo
{
    public class PingFrame : Frame
    {
        public bool Ack { get;set; }

        public override FrameType Type => FrameType.Ping;

        public override byte Flags => Ack ? (byte)0x1 : (byte)0x0;

        public override uint StreamIdentifier => 0x0;

        byte[] opaqueData = new byte[64];

        public byte[] OpaqueData
        {
            get => opaqueData;
            set
            {
                if (opaqueData.Length != 64)
                    throw new ArgumentOutOfRangeException(nameof(value), "Must be 64 bytes of data");

                opaqueData = value;
            }
        }

        public override IEnumerable<byte> Payload => opaqueData;

        public override void ParsePayload (byte[] payloadData, FrameHeader frameHeader)
        {
            Ack = (frameHeader.Flags & 0x1) == 0x1;

            opaqueData = new byte[payloadData.Length];

            if (payloadData != null)
                Array.Copy (payloadData, 0, opaqueData, 0, payloadData.Length);
        }

        public override string ToString() => string.Format("[Frame: PING, Id={0}, Ack={1}, OpaqueData={2}]",
                StreamIdentifier,
                Ack,
                OpaqueData.Length);
    }
}
