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
        public byte[] Content { get; private set; }

        public PacketRecord(int number, RawCapture capture)
        {
            rawCapture = capture;
            No = number;
            packet = capture.GetPacket();
            GetDetail();
        }

        public byte[] MakePcapArchive()
        {
            byte[] arr = new byte[rawCapture.Data.Length + 16];
            byte[] sec = BitConverter.GetBytes((uint)rawCapture.Timeval.Seconds);
            byte[] msec = BitConverter.GetBytes((uint)rawCapture.Timeval.MicroSeconds);
            byte[] incllen = BitConverter.GetBytes((uint)rawCapture.Data.Length);
            byte[] origlen = BitConverter.GetBytes((uint)rawCapture.Data.Length);
            sec.CopyTo(arr, 0);
            msec.CopyTo(arr, 4);
            incllen.CopyTo(arr, 8);
            origlen.CopyTo(arr, 12);
            rawCapture.Data.CopyTo(arr, 16);
            return arr;
        }

        private void GetDetail()
        {
            var ipkt = packet.Extract<IPPacket>();
            if (ipkt != null)
            {
                GetIPPacketDetail(ipkt);
            }
            else
            {
                var apkt = packet.Extract<ArpPacket>();
                GetArpPacketDetail(apkt);
            }

        }

        private void GetArpPacketDetail(ArpPacket apkt)
        {
            Type = apkt.ProtocolAddressType.ToString();
            SourceAddress = apkt.SenderHardwareAddress.ToString();
            DestinationAddress = apkt.TargetHardwareAddress.ToString();
            SourcePort = "N/A";
            DestinationPort = "N/A";
            Content = apkt.Bytes;
        }

        private void GetIPPacketDetail(IPPacket ipkt)
        {
            SourceAddress = ipkt.SourceAddress.ToString();
            DestinationAddress = ipkt.DestinationAddress.ToString();
            Type = ipkt.Protocol.ToString();
            switch (ipkt.Protocol)
            {
                case ProtocolType.Tcp:
                    {
                        var tpkt = ipkt.Extract<TcpPacket>();
                        SourcePort = tpkt.SourcePort.ToString();
                        DestinationPort = tpkt.DestinationPort.ToString();
                        Content = tpkt.Bytes;
                        return;
                    }
                case ProtocolType.Udp:
                    {
                        var upkt = ipkt.Extract<UdpPacket>();
                        SourcePort = upkt.SourcePort.ToString();
                        DestinationPort = upkt.DestinationPort.ToString();
                        Content = upkt.Bytes;
                        return;
                    }
                case ProtocolType.Icmp:
                    {
                        var icpkt = ipkt.Extract<IcmpV4Packet>();
                        SourcePort = "N/A";
                        DestinationPort = "N/A";
                        Content = icpkt.Bytes;
                        return;
                    }
                case ProtocolType.IcmpV6:
                    {
                        var icpkt = ipkt.Extract<IcmpV6Packet>();
                        SourcePort = "N/A";
                        DestinationPort = "N/A";
                        Content = icpkt.Bytes;
                        return;
                    }
                default:
                    {
                        SourcePort = "N/A";
                        DestinationPort = "N/A";
                        Content = ipkt.Bytes;
                        return;
                    }
            }
        }
    }
}
