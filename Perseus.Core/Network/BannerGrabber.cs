using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Perseus.Core.Network
{
    public class BannerGrabber
    {
        private readonly ILogger? _logger;

        public BannerGrabber(ILogger? logger = null)
        {
            _logger = logger;
        }

        public async Task<string?> GrabBannerAsync(
            string ipAddress, 
            int port, 
            int timeout = 3000,
            CancellationToken cancellationToken = default)
        {
            try
            {
                using var tcpClient = new TcpClient();
                var connectTask = tcpClient.ConnectAsync(ipAddress, port);
                var timeoutTask = Task.Delay(timeout, cancellationToken);
                
                var completedTask = await Task.WhenAny(connectTask, timeoutTask);
                
                if (completedTask == connectTask && tcpClient.Connected)
                {
                    using var stream = tcpClient.GetStream();
                    
                    // Send appropriate probe based on port
                    var probe = GetProbeForPort(port);
                    if (!string.IsNullOrEmpty(probe))
                    {
                        var probeBytes = Encoding.ASCII.GetBytes(probe);
                        await stream.WriteAsync(probeBytes, 0, probeBytes.Length, cancellationToken);
                    }

                    // Read response
                    var buffer = new byte[4096];
                    var readTask = stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                    var readTimeoutTask = Task.Delay(2000, cancellationToken);
                    
                    var readCompletedTask = await Task.WhenAny(readTask, readTimeoutTask);
                    
                    if (readCompletedTask == readTask)
                    {
                        var bytesRead = await readTask;
                        if (bytesRead > 0)
                        {
                            var banner = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                            return CleanBanner(banner);
                        }
                    }
                    
                    // If no response to probe, try reading without sending anything (for services that send banner immediately)
                    if (string.IsNullOrEmpty(probe))
                    {
                        await Task.Delay(500, cancellationToken); // Wait a bit for banner
                        if (stream.DataAvailable)
                        {
                            var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                            if (bytesRead > 0)
                            {
                                var banner = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                                return CleanBanner(banner);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogDebug("Erro ao capturar banner de {IpAddress}:{Port}: {Error}", ipAddress, port, ex.Message);
            }

            return null;
        }

        private string GetProbeForPort(int port)
        {
            return port switch
            {
                21 => "", // FTP sends banner immediately
                22 => "", // SSH sends banner immediately
                23 => "", // Telnet sends banner immediately
                25 => "", // SMTP sends banner immediately
                80 => "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                110 => "", // POP3 sends banner immediately
                143 => "", // IMAP sends banner immediately
                443 => "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                993 => "", // IMAPS
                995 => "", // POP3S
                1433 => "", // MSSQL
                3306 => "", // MySQL
                3389 => "", // RDP
                5432 => "", // PostgreSQL
                8080 => "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                8443 => "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                _ => "" // Default: no probe, wait for banner
            };
        }

        private string CleanBanner(string banner)
        {
            if (string.IsNullOrEmpty(banner))
                return string.Empty;

            // Remove control characters and clean up the banner
            var cleaned = new StringBuilder();
            foreach (char c in banner)
            {
                if (c >= 32 && c <= 126) // Printable ASCII characters
                {
                    cleaned.Append(c);
                }
                else if (c == '\n' || c == '\r')
                {
                    cleaned.Append(' ');
                }
            }

            return cleaned.ToString().Trim();
        }

        public async Task<Dictionary<string, string>> GrabDetailedBannerAsync(
            string ipAddress,
            int port,
            int timeout = 5000,
            CancellationToken cancellationToken = default)
        {
            var result = new Dictionary<string, string>();

            try
            {
                var banner = await GrabBannerAsync(ipAddress, port, timeout, cancellationToken);
                if (!string.IsNullOrEmpty(banner))
                {
                    result["raw_banner"] = banner;
                    result["service"] = ExtractServiceInfo(banner, port);
                    result["version"] = ExtractVersionInfo(banner);
                    result["os_info"] = ExtractOSInfo(banner);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning("Erro ao capturar banner detalhado de {IpAddress}:{Port}: {Error}", 
                    ipAddress, port, ex.Message);
            }

            return result;
        }

        private string ExtractServiceInfo(string banner, int port)
        {
            var lowerBanner = banner.ToLower();

            // HTTP services
            if (lowerBanner.Contains("http") || port == 80 || port == 443 || port == 8080 || port == 8443)
            {
                if (lowerBanner.Contains("apache")) return "Apache HTTP Server";
                if (lowerBanner.Contains("nginx")) return "Nginx";
                if (lowerBanner.Contains("iis")) return "Microsoft IIS";
                if (lowerBanner.Contains("lighttpd")) return "Lighttpd";
                return "HTTP Server";
            }

            // SSH
            if (lowerBanner.Contains("ssh") || port == 22)
            {
                if (lowerBanner.Contains("openssh")) return "OpenSSH";
                return "SSH Server";
            }

            // FTP
            if (lowerBanner.Contains("ftp") || port == 21)
            {
                if (lowerBanner.Contains("vsftpd")) return "vsftpd";
                if (lowerBanner.Contains("proftpd")) return "ProFTPD";
                return "FTP Server";
            }

            // Database services
            if (lowerBanner.Contains("mysql") || port == 3306) return "MySQL";
            if (lowerBanner.Contains("postgresql") || port == 5432) return "PostgreSQL";
            if (port == 1433) return "Microsoft SQL Server";

            // Mail services
            if (lowerBanner.Contains("smtp") || port == 25) return "SMTP Server";
            if (lowerBanner.Contains("pop3") || port == 110) return "POP3 Server";
            if (lowerBanner.Contains("imap") || port == 143) return "IMAP Server";

            return "Unknown Service";
        }

        private string ExtractVersionInfo(string banner)
        {
            // Common version patterns
            var patterns = new[]
            {
                @"(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)",  // Generic version pattern
                @"Apache/(\d+\.\d+\.\d+)",          // Apache version
                @"nginx/(\d+\.\d+\.\d+)",           // Nginx version
                @"OpenSSH_(\d+\.\d+)",              // OpenSSH version
                @"Microsoft-IIS/(\d+\.\d+)",        // IIS version
                @"vsftpd (\d+\.\d+\.\d+)",          // vsftpd version
            };

            foreach (var pattern in patterns)
            {
                var match = System.Text.RegularExpressions.Regex.Match(banner, pattern);
                if (match.Success)
                {
                    return match.Groups[1].Value;
                }
            }

            return "Unknown";
        }

        private string ExtractOSInfo(string banner)
        {
            var lowerBanner = banner.ToLower();

            if (lowerBanner.Contains("ubuntu")) return "Ubuntu";
            if (lowerBanner.Contains("debian")) return "Debian";
            if (lowerBanner.Contains("centos")) return "CentOS";
            if (lowerBanner.Contains("redhat") || lowerBanner.Contains("rhel")) return "Red Hat";
            if (lowerBanner.Contains("windows")) return "Windows";
            if (lowerBanner.Contains("freebsd")) return "FreeBSD";
            if (lowerBanner.Contains("openbsd")) return "OpenBSD";
            if (lowerBanner.Contains("linux")) return "Linux";

            return "Unknown";
        }
    }
}

