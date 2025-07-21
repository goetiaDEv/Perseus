using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Perseus.Common.Models;

namespace Perseus.Core.Network
{
    public class HostDiscoverer
    {
        private readonly ILogger<HostDiscoverer>? _logger;

        public HostDiscoverer(ILogger<HostDiscoverer>? logger = null)
        {
            _logger = logger;
        }

        public async Task<List<HostResult>> DiscoverHostsAsync(
            string subnet, 
            CancellationToken cancellationToken = default, 
            Action<HostResult>? onHostFound = null,
            int timeout = 1000,
            int maxConcurrency = 50)
        {
            var activeHosts = new List<HostResult>();
            var semaphore = new SemaphoreSlim(maxConcurrency, maxConcurrency);
            var tasks = new List<Task>();

            _logger?.LogInformation("Iniciando descoberta de hosts na subnet {Subnet}", subnet);

            // Parse subnet (support for CIDR notation)
            var (baseIp, startRange, endRange) = ParseSubnet(subnet);

            for (int i = startRange; i <= endRange; i++)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                string ip = $"{baseIp}.{i}";
                
                tasks.Add(Task.Run(async () =>
                {
                    await semaphore.WaitAsync(cancellationToken);
                    try
                    {
                        var hostResult = await PingHostAsync(ip, timeout, cancellationToken);
                        if (hostResult.IsAlive)
                        {
                            onHostFound?.Invoke(hostResult);
                            lock (activeHosts)
                            {
                                activeHosts.Add(hostResult);
                            }
                            _logger?.LogDebug("Host ativo encontrado: {IpAddress}", hostResult.IpAddress);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogWarning("Erro ao verificar host {Ip}: {Error}", ip, ex.Message);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }, cancellationToken));
            }

            await Task.WhenAll(tasks);
            _logger?.LogInformation("Descoberta concluída. {Count} hosts ativos encontrados", activeHosts.Count);
            
            return activeHosts;
        }

        public async Task<List<HostResult>> DiscoverHostsFromListAsync(
            List<string> targets,
            CancellationToken cancellationToken = default,
            Action<HostResult>? onHostFound = null,
            int timeout = 1000,
            int maxConcurrency = 50)
        {
            var activeHosts = new List<HostResult>();
            var semaphore = new SemaphoreSlim(maxConcurrency, maxConcurrency);
            var tasks = new List<Task>();

            _logger?.LogInformation("Iniciando descoberta de hosts para {Count} alvos", targets.Count);

            foreach (var target in targets)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                tasks.Add(Task.Run(async () =>
                {
                    await semaphore.WaitAsync(cancellationToken);
                    try
                    {
                        var hostResult = await PingHostAsync(target, timeout, cancellationToken);
                        if (hostResult.IsAlive)
                        {
                            onHostFound?.Invoke(hostResult);
                            lock (activeHosts)
                            {
                                activeHosts.Add(hostResult);
                            }
                            _logger?.LogDebug("Host ativo encontrado: {IpAddress}", hostResult.IpAddress);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogWarning("Erro ao verificar host {Target}: {Error}", target, ex.Message);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }, cancellationToken));
            }

            await Task.WhenAll(tasks);
            _logger?.LogInformation("Descoberta concluída. {Count} hosts ativos encontrados", activeHosts.Count);
            
            return activeHosts;
        }

        private async Task<HostResult> PingHostAsync(string target, int timeout, CancellationToken cancellationToken)
        {
            var hostResult = new HostResult { IpAddress = target };

            try
            {
                // Try to resolve hostname if it's not an IP
                if (!IPAddress.TryParse(target, out var ipAddress))
                {
                    var hostEntry = await Dns.GetHostEntryAsync(target);
                    if (hostEntry.AddressList.Length > 0)
                    {
                        ipAddress = hostEntry.AddressList[0];
                        hostResult.IpAddress = ipAddress.ToString();
                        hostResult.Hostname = target;
                    }
                    else
                    {
                        return hostResult;
                    }
                }
                else
                {
                    // Try reverse DNS lookup
                    try
                    {
                        var hostEntry = await Dns.GetHostEntryAsync(ipAddress);
                        hostResult.Hostname = hostEntry.HostName;
                    }
                    catch
                    {
                        // Ignore reverse DNS failures
                    }
                }

                using var pinger = new Ping();
                var reply = await pinger.SendPingAsync(hostResult.IpAddress, timeout);
                
                if (reply.Status == IPStatus.Success)
                {
                    hostResult.IsAlive = true;
                }
            }
            catch (PingException)
            {
                // Host not reachable
            }
            catch (Exception ex)
            {
                _logger?.LogWarning("Erro inesperado ao fazer ping em {Target}: {Error}", target, ex.Message);
            }

            return hostResult;
        }

        private (string baseIp, int startRange, int endRange) ParseSubnet(string subnet)
        {
            // Support for different formats:
            // 192.168.1.0/24
            // 192.168.1.1-254
            // 192.168.1 (assumes .1-254)
            
            if (subnet.Contains('/'))
            {
                // CIDR notation
                var parts = subnet.Split('/');
                var ip = parts[0];
                var cidr = int.Parse(parts[1]);
                
                // For simplicity, assume /24 networks for now
                var ipParts = ip.Split('.');
                var baseIp = $"{ipParts[0]}.{ipParts[1]}.{ipParts[2]}";
                
                return (baseIp, 1, 254);
            }
            else if (subnet.Contains('-'))
            {
                // Range notation
                var parts = subnet.Split('-');
                var ipParts = parts[0].Split('.');
                var baseIp = $"{ipParts[0]}.{ipParts[1]}.{ipParts[2]}";
                var startRange = int.Parse(ipParts[3]);
                var endRange = int.Parse(parts[1]);
                
                return (baseIp, startRange, endRange);
            }
            else
            {
                // Assume it's a base IP (e.g., 192.168.1)
                return (subnet, 1, 254);
            }
        }
    }
}

