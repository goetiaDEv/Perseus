using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Perseus.Common.Models;

namespace Perseus.Core.Network
{
    public class PortScanner
    {
        private readonly ILogger<PortScanner>? _logger;
        private readonly BannerGrabber _bannerGrabber;

        public PortScanner(ILogger<PortScanner>? logger = null)
        {
            _logger = logger;
            _bannerGrabber = new BannerGrabber(logger);
        }

        public async Task<List<PortResult>> ScanPortsAsync(
            string ipAddress, 
            List<int> ports, 
            CancellationToken cancellationToken = default, 
            Action<PortResult>? onPortFound = null,
            int timeout = 1000,
            int maxConcurrency = 100,
            bool grabBanners = true)
        {
            var openPorts = new List<PortResult>();
            var semaphore = new SemaphoreSlim(maxConcurrency, maxConcurrency);
            var tasks = new List<Task>();

            _logger?.LogInformation("Iniciando varredura de portas em {IpAddress} - {PortCount} portas", ipAddress, ports.Count);

            foreach (var port in ports)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                tasks.Add(Task.Run(async () =>
                {
                    await semaphore.WaitAsync(cancellationToken);
                    try
                    {
                        var portResult = await ScanPortAsync(ipAddress, port, timeout, grabBanners, cancellationToken);
                        if (portResult.State == "Open")
                        {
                            onPortFound?.Invoke(portResult);
                            lock (openPorts)
                            {
                                openPorts.Add(portResult);
                            }
                            _logger?.LogDebug("Porta aberta encontrada: {IpAddress}:{Port} ({Service})", 
                                ipAddress, port, portResult.Service ?? "Unknown");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogWarning("Erro ao escanear porta {Port} em {IpAddress}: {Error}", 
                            port, ipAddress, ex.Message);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }, cancellationToken));
            }

            await Task.WhenAll(tasks);
            openPorts.Sort((a, b) => a.Port.CompareTo(b.Port));
            
            _logger?.LogInformation("Varredura concluída. {Count} portas abertas encontradas em {IpAddress}", 
                openPorts.Count, ipAddress);
            
            return openPorts;
        }

        public async Task<List<PortResult>> ScanPortRangesAsync(
            string ipAddress,
            List<string> portRanges,
            CancellationToken cancellationToken = default,
            Action<PortResult>? onPortFound = null,
            int timeout = 1000,
            int maxConcurrency = 100,
            bool grabBanners = true)
        {
            var ports = ParsePortRanges(portRanges);
            return await ScanPortsAsync(ipAddress, ports, cancellationToken, onPortFound, timeout, maxConcurrency, grabBanners);
        }

        private async Task<PortResult> ScanPortAsync(
            string ipAddress, 
            int port, 
            int timeout, 
            bool grabBanner,
            CancellationToken cancellationToken)
        {
            var portResult = new PortResult
            {
                Port = port,
                Protocol = "TCP",
                State = "Closed"
            };

            try
            {
                using var tcpClient = new TcpClient();
                var connectTask = tcpClient.ConnectAsync(ipAddress, port);
                var timeoutTask = Task.Delay(timeout, cancellationToken);
                
                var completedTask = await Task.WhenAny(connectTask, timeoutTask);
                
                if (completedTask == connectTask && !cancellationToken.IsCancellationRequested)
                {
                    if (tcpClient.Connected)
                    {
                        portResult.State = "Open";
                        portResult.Service = GetServiceName(port);
                        
                        if (grabBanner)
                        {
                            try
                            {
                                var banner = await _bannerGrabber.GrabBannerAsync(ipAddress, port, 2000, cancellationToken);
                                if (!string.IsNullOrEmpty(banner))
                                {
                                    portResult.Banner = banner;
                                    portResult.Version = ExtractVersionFromBanner(banner);
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger?.LogDebug("Falha ao capturar banner para {IpAddress}:{Port}: {Error}", 
                                    ipAddress, port, ex.Message);
                            }
                        }
                    }
                }
                else if (completedTask == timeoutTask)
                {
                    portResult.State = "Filtered";
                }
            }
            catch (SocketException)
            {
                // Porta fechada ou filtrada
                portResult.State = "Closed";
            }
            catch (OperationCanceledException)
            {
                // Operação cancelada
                portResult.State = "Cancelled";
            }

            return portResult;
        }

        private List<int> ParsePortRanges(List<string> portRanges)
        {
            var ports = new HashSet<int>();

            foreach (var range in portRanges)
            {
                if (range.Contains('-'))
                {
                    var parts = range.Split('-');
                    if (parts.Length == 2 && 
                        int.TryParse(parts[0], out var start) && 
                        int.TryParse(parts[1], out var end))
                    {
                        for (int i = start; i <= end && i <= 65535; i++)
                        {
                            ports.Add(i);
                        }
                    }
                }
                else if (int.TryParse(range, out var singlePort))
                {
                    ports.Add(singlePort);
                }
            }

            return ports.ToList();
        }

        private string? GetServiceName(int port)
        {
            // Common port to service mapping
            var commonPorts = new Dictionary<int, string>
            {
                { 21, "FTP" },
                { 22, "SSH" },
                { 23, "Telnet" },
                { 25, "SMTP" },
                { 53, "DNS" },
                { 80, "HTTP" },
                { 110, "POP3" },
                { 143, "IMAP" },
                { 443, "HTTPS" },
                { 993, "IMAPS" },
                { 995, "POP3S" },
                { 1433, "MSSQL" },
                { 3306, "MySQL" },
                { 3389, "RDP" },
                { 5432, "PostgreSQL" },
                { 5900, "VNC" },
                { 8080, "HTTP-Alt" },
                { 8443, "HTTPS-Alt" }
            };

            return commonPorts.TryGetValue(port, out var service) ? service : null;
        }

        private string? ExtractVersionFromBanner(string banner)
        {
            // Simple version extraction patterns
            var patterns = new[]
            {
                @"(\d+\.\d+(?:\.\d+)?)",  // Generic version pattern
                @"Server: (.+)",          // HTTP Server header
                @"SSH-(\d+\.\d+)",        // SSH version
                @"FTP (.+)",              // FTP version
            };

            foreach (var pattern in patterns)
            {
                var match = System.Text.RegularExpressions.Regex.Match(banner, pattern);
                if (match.Success)
                {
                    return match.Groups[1].Value.Trim();
                }
            }

            return null;
        }

        public static List<int> GetCommonPorts()
        {
            return new List<int>
            {
                21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 9090, 9443
            };
        }

        public static List<int> GetTopPorts(int count = 1000)
        {
            // Top 1000 most common ports (simplified list)
            var topPorts = new List<int>();
            
            // Add common ports first
            topPorts.AddRange(GetCommonPorts());
            
            // Add additional ports up to the requested count
            for (int i = 1; i <= 65535 && topPorts.Count < count; i++)
            {
                if (!topPorts.Contains(i))
                {
                    topPorts.Add(i);
                }
            }
            
            return topPorts.Take(count).ToList();
        }
    }
}

