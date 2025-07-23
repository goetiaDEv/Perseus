using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Perseus.Common.Models;
using Perseus.Core.Network;
using Perseus.Core.Vulnerability;

namespace Perseus.CLI.Commands
{
    public class AttackCommands
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<AttackCommands> _logger;

        public AttackCommands(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
            _logger = serviceProvider.GetRequiredService<ILogger<AttackCommands>>();
        }

        public void ConfigureCommands(Command attackCommand)
        {
            // Host discovery command
            var discoverCommand = new Command("discover", "Descobrir hosts ativos na rede");
            var targetArgument = new Argument<string>("target", "Alvo (subnet, IP range ou lista de IPs)");
            var timeoutOption = new Option<int>("--timeout", () => 1000, "Timeout em milissegundos");
            var threadsOption = new Option<int>("--threads", () => 50, "Número de threads");
            var outputOption = new Option<string?>("--output", "Arquivo de saída");

            discoverCommand.AddArgument(targetArgument);
            discoverCommand.AddOption(timeoutOption);
            discoverCommand.AddOption(threadsOption);
            discoverCommand.AddOption(outputOption);

            discoverCommand.SetHandler(async (target, timeout, threads, output) =>
            {
                await ExecuteHostDiscovery(target, timeout, threads, output);
            }, targetArgument, timeoutOption, threadsOption, outputOption);

            attackCommand.AddCommand(discoverCommand);

            // Port scanning command
            var scanCommand = new Command("scan", "Escanear portas em hosts");
            var hostArgument = new Argument<string>("host", "Host ou IP para escanear");
            var portsOption = new Option<string[]>("--ports", () => new[] { "1-1000" }, "Portas ou ranges para escanear");
            var bannerOption = new Option<bool>("--banner", () => true, "Capturar banners dos serviços");
            var scanTimeoutOption = new Option<int>("--timeout", () => 1000, "Timeout em milissegundos");
            var scanThreadsOption = new Option<int>("--threads", () => 100, "Número de threads");
            var scanOutputOption = new Option<string?>("--output", "Arquivo de saída");

            scanCommand.AddArgument(hostArgument);
            scanCommand.AddOption(portsOption);
            scanCommand.AddOption(bannerOption);
            scanCommand.AddOption(scanTimeoutOption);
            scanCommand.AddOption(scanThreadsOption);
            scanCommand.AddOption(scanOutputOption);

            scanCommand.SetHandler(async (host, ports, banner, timeout, threads, output) =>
            {
                await ExecutePortScan(host, ports, banner, timeout, threads, output);
            }, hostArgument, portsOption, bannerOption, scanTimeoutOption, scanThreadsOption, scanOutputOption);

            attackCommand.AddCommand(scanCommand);

            // Vulnerability assessment command
            var vulnCommand = new Command("vuln", "Avaliar vulnerabilidades em serviços");
            var vulnHostArgument = new Argument<string>("host", "Host ou IP para avaliar");
            var vulnPortsOption = new Option<string[]>("--ports", () => new[] { "1-1000" }, "Portas para escanear");
            var minCvssOption = new Option<double>("--min-cvss", () => 0.0, "Score CVSS mínimo");
            var vulnOutputOption = new Option<string?>("--output", "Arquivo de saída");

            vulnCommand.AddArgument(vulnHostArgument);
            vulnCommand.AddOption(vulnPortsOption);
            vulnCommand.AddOption(minCvssOption);
            vulnCommand.AddOption(vulnOutputOption);

            vulnCommand.SetHandler(async (host, ports, minCvss, output) =>
            {
                await ExecuteVulnerabilityAssessment(host, ports, minCvss, output);
            }, vulnHostArgument, vulnPortsOption, minCvssOption, vulnOutputOption);

            attackCommand.AddCommand(vulnCommand);

            // Full attack command (combines all)
            var fullCommand = new Command("full", "Executar avaliação completa (descoberta + scan + vulnerabilidades)");
            var fullTargetArgument = new Argument<string>("target", "Alvo (subnet, IP range ou IP específico)");
            var fullPortsOption = new Option<string[]>("--ports", () => new[] { "1-1000" }, "Portas para escanear");
            var fullMinCvssOption = new Option<double>("--min-cvss", () => 4.0, "Score CVSS mínimo");
            var fullOutputOption = new Option<string?>("--output", "Arquivo de saída");
            var stealthOption = new Option<bool>("--stealth", () => false, "Modo stealth (mais lento, menos detectável)");

            fullCommand.AddArgument(fullTargetArgument);
            fullCommand.AddOption(fullPortsOption);
            fullCommand.AddOption(fullMinCvssOption);
            fullCommand.AddOption(fullOutputOption);
            fullCommand.AddOption(stealthOption);

            fullCommand.SetHandler(async (target, ports, minCvss, output, stealth) =>
            {
                await ExecuteFullAssessment(target, ports, minCvss, output, stealth);
            }, fullTargetArgument, fullPortsOption, fullMinCvssOption, fullOutputOption, stealthOption);

            attackCommand.AddCommand(fullCommand);
        }

        private async Task ExecuteHostDiscovery(string target, int timeout, int threads, string? output)
        {
            _logger.LogInformation("Iniciando descoberta de hosts para: {Target}", target);

            var hostDiscoverer = _serviceProvider.GetRequiredService<HostDiscoverer>();
            var hosts = new List<HostResult>();

            try
            {
                if (target.Contains('/') || target.Contains('-') || !target.Contains('.'))
                {
                    // Subnet or range
                    hosts = await hostDiscoverer.DiscoverHostsAsync(
                        target,
                        CancellationToken.None,
                        host => Console.WriteLine($"[+] Host ativo encontrado: {host.IpAddress}"),
                        timeout,
                        threads);
                }
                else
                {
                    // Single host or list
                    var targets = target.Split(',').Select(t => t.Trim()).ToList();
                    hosts = await hostDiscoverer.DiscoverHostsFromListAsync(
                        targets,
                        CancellationToken.None,
                        host => Console.WriteLine($"[+] Host ativo encontrado: {host.IpAddress}"),
                        timeout,
                        threads);
                }

                Console.WriteLine($"\n[*] Descoberta concluída. {hosts.Count} hosts ativos encontrados.");

                foreach (var host in hosts)
                {
                    Console.WriteLine($"  - {host.IpAddress}" + 
                        (string.IsNullOrEmpty(host.Hostname) ? "" : $" ({host.Hostname})"));
                }

                if (!string.IsNullOrEmpty(output))
                {
                    await SaveResultsToFile(hosts, output);
                    Console.WriteLine($"[*] Resultados salvos em: {output}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro durante a descoberta de hosts");
                Console.WriteLine($"[!] Erro: {ex.Message}");
            }
        }

        private async Task ExecutePortScan(string host, string[] ports, bool banner, int timeout, int threads, string? output)
        {
            _logger.LogInformation("Iniciando varredura de portas em: {Host}", host);

            var portScanner = _serviceProvider.GetRequiredService<PortScanner>();

            try
            {
                var openPorts = await portScanner.ScanPortRangesAsync(
                    host,
                    ports.ToList(),
                    CancellationToken.None,
                    port => Console.WriteLine($"[+] Porta aberta: {host}:{port.Port} ({port.Service ?? "Unknown"})"),
                    timeout,
                    threads,
                    banner);

                Console.WriteLine($"\n[*] Varredura concluída. {openPorts.Count} portas abertas encontradas.");

                foreach (var port in openPorts)
                {
                    Console.WriteLine($"  - {port.Port}/{port.Protocol} - {port.Service ?? "Unknown"}");
                    if (!string.IsNullOrEmpty(port.Banner))
                    {
                        Console.WriteLine($"    Banner: {port.Banner}");
                    }
                    if (!string.IsNullOrEmpty(port.Version))
                    {
                        Console.WriteLine($"    Versão: {port.Version}");
                    }
                }

                if (!string.IsNullOrEmpty(output))
                {
                    var hostResult = new HostResult
                    {
                        IpAddress = host,
                        IsAlive = true,
                        OpenPorts = openPorts
                    };
                    await SaveResultsToFile(new List<HostResult> { hostResult }, output);
                    Console.WriteLine($"[*] Resultados salvos em: {output}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro durante a varredura de portas");
                Console.WriteLine($"[!] Erro: {ex.Message}");
            }
        }

        private async Task ExecuteVulnerabilityAssessment(string host, string[] ports, double minCvss, string? output)
        {
            _logger.LogInformation("Iniciando avaliação de vulnerabilidades em: {Host}", host);

            var portScanner = _serviceProvider.GetRequiredService<PortScanner>();
            var cveChecker = _serviceProvider.GetRequiredService<CveChecker>();

            try
            {
                // First scan ports to identify services
                Console.WriteLine("[*] Escaneando portas e identificando serviços...");
                var openPorts = await portScanner.ScanPortRangesAsync(
                    host,
                    ports.ToList(),
                    CancellationToken.None,
                    null,
                    1000,
                    100,
                    true);

                // Convert ports to services
                var services = openPorts.Select(port => new ServiceResult
                {
                    Name = port.Service ?? "Unknown",
                    Version = port.Version,
                    Port = port.Port,
                    Protocol = port.Protocol
                }).Where(s => s.Name != "Unknown").ToList();

                Console.WriteLine($"[*] {services.Count} serviços identificados. Verificando vulnerabilidades...");

                // Check vulnerabilities
                var vulnerabilities = await cveChecker.CheckVulnerabilitiesAsync(
                    services,
                    CancellationToken.None,
                    minCvss);

                Console.WriteLine($"\n[*] Avaliação concluída. {vulnerabilities.Count} vulnerabilidades encontradas.");

                foreach (var vuln in vulnerabilities.Take(10)) // Show top 10
                {
                    Console.WriteLine($"\n[!] {vuln.CveId} - {vuln.Severity} (CVSS: {vuln.CvssScore:F1})");
                    Console.WriteLine($"    Serviço: {vuln.AffectedService}");
                    Console.WriteLine($"    Título: {vuln.Title}");
                    if (vuln.IsExploitable)
                    {
                        Console.WriteLine($"    [!] EXPLORÁVEL");
                    }
                }

                if (vulnerabilities.Count > 10)
                {
                    Console.WriteLine($"\n[*] ... e mais {vulnerabilities.Count - 10} vulnerabilidades.");
                }

                if (!string.IsNullOrEmpty(output))
                {
                    var scanResult = new ScanResult
                    {
                        Target = host,
                        ScanTime = DateTime.Now,
                        Type = ScanType.VulnerabilityAssessment,
                        Hosts = new List<HostResult>
                        {
                            new HostResult
                            {
                                IpAddress = host,
                                IsAlive = true,
                                OpenPorts = openPorts,
                                Services = services
                            }
                        },
                        Vulnerabilities = vulnerabilities,
                        Status = ScanStatus.Completed
                    };

                    await SaveScanResultToFile(scanResult, output);
                    Console.WriteLine($"[*] Resultados salvos em: {output}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro durante a avaliação de vulnerabilidades");
                Console.WriteLine($"[!] Erro: {ex.Message}");
            }
        }

        private async Task ExecuteFullAssessment(string target, string[] ports, double minCvss, string? output, bool stealth)
        {
            _logger.LogInformation("Iniciando avaliação completa para: {Target}", target);

            var timeout = stealth ? 3000 : 1000;
            var threads = stealth ? 10 : 50;

            try
            {
                // Step 1: Host Discovery
                Console.WriteLine("[*] Fase 1: Descoberta de hosts...");
                await ExecuteHostDiscovery(target, timeout, threads, null);

                // Step 2: Port Scanning (for discovered hosts)
                // For simplicity, assume single host for now
                Console.WriteLine("\n[*] Fase 2: Varredura de portas...");
                await ExecutePortScan(target, ports, true, timeout, threads * 2, null);

                // Step 3: Vulnerability Assessment
                Console.WriteLine("\n[*] Fase 3: Avaliação de vulnerabilidades...");
                await ExecuteVulnerabilityAssessment(target, ports, minCvss, output);

                Console.WriteLine("\n[*] Avaliação completa finalizada!");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro durante a avaliação completa");
                Console.WriteLine($"[!] Erro: {ex.Message}");
            }
        }

        private async Task SaveResultsToFile(List<HostResult> hosts, string filename)
        {
            var json = System.Text.Json.JsonSerializer.Serialize(hosts, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true
            });
            await File.WriteAllTextAsync(filename, json);
        }

        private async Task SaveScanResultToFile(ScanResult scanResult, string filename)
        {
            var json = System.Text.Json.JsonSerializer.Serialize(scanResult, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true
            });
            await File.WriteAllTextAsync(filename, json);
        }
    }
}

