using SharpPcap;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
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

namespace WpfApp1
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly CaptureDeviceList devices;
        private ILiveDevice device;
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
            packetCount = 0;
            packetQueue = new();
            Records.Clear();
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
                device.Close();
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

        }

        private void IPTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {

        }

        private void ResetButton_Click(object sender, RoutedEventArgs e)
        {

        }

        private void InterfaceComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            device = (from d in devices where d.Description == InterfaceComboBox.SelectedItem.ToString() select d).ToArray()[0];
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
                            foreach (var packet in packetQueue.Reverse())
                            {
                                Records.Add(packet);
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
        }
    }
}
