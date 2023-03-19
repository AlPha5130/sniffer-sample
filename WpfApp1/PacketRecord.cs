using PacketDotNet;
using SharpPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WpfApp1
{
    public class PacketRecord
    {
        private readonly RawCapture rawCapture;
        public int No { get; private set; }
        private readonly Packet packet;
        public string SourceAddress { get; private set; }
        public string DestinationAddress { get; private set; }
        public string SourcePort { get; private set; }
        public string DestinationPort { get; private set; }
        public string Type { get; private set; }
        public int Length { get { return rawCapture.PacketLength; } }
        public string Timestamp { get { return rawCapture.Timeval.Date.ToString(); } }

        public PacketRecord(int count, RawCapture capture)
        {
            rawCapture = capture;
            No = count;
            packet = capture.GetPacket();
        }

        private void GetDetail()
        {

        }
    }
}
