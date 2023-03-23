using Microsoft.Win32;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Sniffer
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly CaptureDeviceList devices;
        private ICaptureDevice device;
        public ObservableCollection<PacketRecord> Records { get; private set; }
        private bool captureRunning = false;

        private bool backgroundThreadStop = true;
        private readonly object queueLock = new();
        private Thread backgroundThread;

        private List<RawCapture> captureList = new();
        private Queue<PacketRecord> packetQueue = new();
        private int packetCount = 0;
        private DateTime lastStatisticsOutput = DateTime.MinValue;
        private readonly TimeSpan updateStatisticsInterval = new(0, 0, 1);
        private bool statisticsNeedsUpdate = false;
        private ICaptureStatistics captureStatistics;

        private readonly StringBuilder builder = new();

        public MainWindow()
        {
            InitializeComponent();
            Records = new();
            PacketList.ItemsSource = Records;
            devices = CaptureDeviceList.Instance;
            if (devices.Count < 1)
            {
                MessageBox.Show("No devices found.");
                Application.Current.Shutdown();
                return;
            }
            foreach (var device in devices)
            {
                InterfaceComboBox.Items.Add(device.Description);
                InterfaceComboBox.SelectedIndex = 0;
            }
        }

        private void AddPacketRecord(object s, PacketCapture e)
        {
            var now = DateTime.Now;
            var interval = now - lastStatisticsOutput;
            if (interval > updateStatisticsInterval)
            {
                statisticsNeedsUpdate = true;
                captureStatistics = e.Device.Statistics;
                lastStatisticsOutput = now;
            }
            lock (queueLock)
            {
                captureList.Add(e.GetPacket());
            }
        }

        private void StartButton_Click(object sender, RoutedEventArgs e)
        {
            lastStatisticsOutput = DateTime.Now;

            StartCapture();

            StartButton.IsEnabled = false;
            StopButton.IsEnabled = true;
            ClearButton.IsEnabled = false;
        }

        private void StartCapture()
        {
            backgroundThreadStop = false;
            backgroundThread = new Thread(BackgroundThread);
            backgroundThread.Start();

            device.OnPacketArrival += AddPacketRecord;
            device.Open();

            captureStatistics = device.Statistics;
            UpdateStatistics();

            device.StartCapture();
            captureRunning = true;
        }

        private void StopCapture()
        {
            if (captureRunning)
            {
                device.StopCapture();
                device.OnPacketArrival -= AddPacketRecord;

                backgroundThreadStop = true;
                backgroundThread.Join();

                captureRunning = false;
            }
        }

        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            StopCapture();

            StartButton.IsEnabled = true;
            StopButton.IsEnabled = false;
            ClearButton.IsEnabled = true;
        }

        private void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            ClearUI();
            ClearCounter();
        }

        private void InterfaceComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            device = (from d in devices where d.Description == InterfaceComboBox.SelectedItem.ToString() select d).ToArray()[0];
        }

        private void ClearUI()
        {
            Records.Clear();
            captureList.Clear();
            packetQueue.Clear();
            HexContent.Clear();
        }

        private void ClearCounter()
        {
            packetCount = 0;
            packetQueue = new();
        }

        private void BackgroundThread()
        {
            while (!backgroundThreadStop)
            {
                bool shouldSleep = true;
                lock (queueLock)
                {
                    if (captureList.Count != 0)
                    {
                        shouldSleep = false;
                    }
                }
                if (shouldSleep)
                {
                    Thread.Sleep(250);
                }
                else
                {
                    List<RawCapture> workingList;
                    lock (queueLock)
                    {
                        workingList = captureList;
                        captureList = new ();
                    }

                    foreach (var capture in workingList)
                    {
                        PacketRecord packetRecord = new(packetCount, capture);
                        Dispatcher.BeginInvoke(() => { packetQueue.Enqueue(packetRecord); });

                        packetCount++;

                        var time = capture.Timeval.Date;
                        var length = capture.Data.Length;
                    }

                    if (statisticsNeedsUpdate)
                    {
                        Dispatcher.BeginInvoke(() =>
                        {
                            while (packetQueue.Count != 0)
                            {
                                var item = packetQueue.Dequeue();
                                Records.Add(item);
                            }
                        });
                        UpdateStatistics();
                        statisticsNeedsUpdate = false;
                    }
                }
            }
        }

        private void UpdateStatistics()
        {
            Dispatcher.BeginInvoke(() =>
            {
                StatusText.Text = $"Received {captureStatistics.ReceivedPackets} packets, dropped {captureStatistics.DroppedPackets} packets, interface dropped {captureStatistics.InterfaceDroppedPackets} packets.";
            });
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            StopCapture();
            device.Close();
        }

        private void PacketList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            HexContent.Clear();
            if (e.AddedItems.Count > 0)
            {
                var selectedRecord = e.AddedItems[0];
                if (selectedRecord != null)
                {
                    FillHex(((PacketRecord)selectedRecord).Content);
                }
            }
        }

        private void FillHex(byte[] data)
        {
            int height = (int)Math.Ceiling(data.Length / 16.0);
            builder.Clear();
            builder.AppendLine("       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");
            for (int i = 0; i < height; i++)
            {
                int start = i * 16;
                int end = Math.Min(i * 16 + 15, data.Length - 1) + 1;
                int padBytes = (i + 1) * 16 - end;
                byte[] slice = data[start..end];
                builder.Append((i * 16).ToString("X6"));
                foreach (byte b in slice)
                {
                    builder.Append($" {b.ToString("X2")}");
                }
                builder.Append("".PadRight(padBytes * 3));
                builder.Append("    ");
                foreach (byte b in slice)
                {
                    builder.Append(b > 31 && b < 128 ? (char)b : '.');
                }
                builder.AppendLine();
            }
            HexContent.Text = builder.ToString();
        }

        private void LoadButton_Click(object sender, RoutedEventArgs e)
        {
            int no = 0;
            OpenFileDialog ofd = new()
            {
                Filter = "Pcap File(*.pcap)|*.pcap",
                Multiselect = false
            };
            ofd.ShowDialog();
            if (ofd.FileName != "")
            {
                device = new CaptureFileReaderDevice(ofd.FileName);
                ClearUI();
                ClearCounter();
                device.OnPacketArrival += (object s, PacketCapture e) =>
                {
                    var packet = new PacketRecord(no, e.GetPacket());
                    no++;
                    Records.Add(packet);
                };
                device.Open();
                device.Capture();
                StatusText.Text = $"Read {no} packets.";
            }
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            if (Records.Count == 0)
            {
                MessageBox.Show("No records to save.", "Demo capture", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            SaveFileDialog sfd = new()
            {
                Filter = "Pcap File(*.pcap)|*.pcap",
            };
            sfd.ShowDialog();
            if (sfd.FileName != "")
            {
                using var stream = File.Open(sfd.FileName, FileMode.Create);
                using BinaryWriter writer = new(stream);
                writer.Write(0xa1b2c3d4);
                writer.Write((ushort)0x2);
                writer.Write((ushort)0x4);
                writer.Write(0);
                writer.Write((uint)0);
                writer.Write((uint)65535);
                writer.Write((uint)device.LinkType);
                foreach (var rec in Records)
                {
                    stream.Write(rec.MakePcapArchive());
                }
            }
        }
    }
}
