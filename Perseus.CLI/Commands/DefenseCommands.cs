using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Perseus.Common.Models;
using Perseus.Core.Network;

namespace Perseus.CLI.Commands
{
    public class DefenseCommands
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<DefenseCommands> _logger;

        public DefenseCommands(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
            _logger = serviceProvider.GetRequiredService<ILogger<DefenseCommands>>();
        }

        public void ConfigureCommands(Command defenseCommand)
        {
            // Network monitoring command
            var monitorCommand = new Command("monitor", "Monitorar rede em busca de atividades suspeitas");
            var networkArgument = new Argument<string>("network", "Rede para monitorar (ex: 192.168.1.0/24)");
            var intervalOption = new Option<int>("--interval", () => 60, "Intervalo de monitoramento em segundos");
            var alertsOption = new Option<string?>("--alerts", "Arquivo para salvar alertas");
            var baselineOption = new Option<string?>("--baseline", "Arquivo de baseline para comparação");

            monitorCommand.AddArgument(networkArgument);
            monitorCommand.AddOption(intervalOption);
            monitorCommand.AddOption(alertsOption);
            monitorCommand.AddOption(baselineOption);

            monitorCommand.SetHandler(async (network, interval, alerts, baseline) =>
            {
                await ExecuteNetworkMonitoring(network, interval, alerts, baseline);
            }, networkArgument, intervalOption, alertsOption, baselineOption);

            defenseCommand.AddCommand(monitorCommand);

            // Baseline creation command
            var baselineCommand = new Command("baseline", "Criar baseline da rede para detecção de anomalias");
            var baselineNetworkArgument = new Argument<string>("network", "Rede para criar baseline");
            var baselineOutputOption = new Option<string>("--output", "Arquivo de saída do baseline") { IsRequired = true };
            var baselineDurationOption = new Option<int>("--duration", () => 300, "Duração da coleta em segundos");

            baselineCommand.AddArgument(baselineNetworkArgument);
            baselineCommand.AddOption(baselineOutputOption);
            baselineCommand.AddOption(baselineDurationOption);

            baselineCommand.SetHandler(async (network, output, duration) =>
            {
                await ExecuteBaselineCreation(network, output, duration);
            }, baselineNetworkArgument, baselineOutputOption, baselineDurationOption);

            defenseCommand.AddCommand(baselineCommand);

            // Log analysis command
            var logCommand = new Command("logs", "Analisar logs em busca de atividades suspeitas");
            var logFileArgument = new Argument<string>("logfile", "Arquivo de log para analisar");
            var logTypeOption = new Option<string>("--type", () => "auto", "Tipo de log (auto, apache, nginx, ssh, windows)");
            var logOutputOption = new Option<string?>("--output", "Arquivo de saída dos alertas");
            var logRulesOption = new Option<string?>("--rules", "Arquivo de regras customizadas");

            logCommand.AddArgument(logFileArgument);
            logCommand.AddOption(logTypeOption);
            logCommand.AddOption(logOutputOption);
            logCommand.AddOption(logRulesOption);

            logCommand.SetHandler(async (logFile, logType, output, rules) =>
            {
                await ExecuteLogAnalysis(logFile, logType, output, rules);
            }, logFileArgument, logTypeOption, logOutputOption, logRulesOption);

            defenseCommand.AddCommand(logCommand);

            // Threat hunting command
            var huntCommand = new Command("hunt", "Buscar ameaças específicas na rede");
            var huntNetworkArgument = new Argument<string>("network", "Rede para buscar ameaças");
            var huntTypeOption = new Option<string[]>("--threats", () => new[] { "malware", "backdoors", "lateral-movement" }, "Tipos de ameaças para buscar");
            var huntOutputOption = new Option<string?>("--output", "Arquivo de saída dos resultados");
            var huntDeepOption = new Option<bool>("--deep", () => false, "Análise profunda (mais lenta)");

            huntCommand.AddArgument(huntNetworkArgument);
            huntCommand.AddOption(huntTypeOption);
            huntCommand.AddOption(huntOutputOption);
            huntCommand.AddOption(huntDeepOption);

            huntCommand.SetHandler(async (network, threats, output, deep) =>
            {
                await ExecuteThreatHunting(network, threats, output, deep);
            }, huntNetworkArgument, huntTypeOption, huntOutputOption, huntDeepOption);

            defenseCommand.AddCommand(huntCommand);

            // Incident response command
            var incidentCommand = new Command("incident", "Responder a incidentes de segurança");
            var incidentTypeArgument = new Argument<string>("type", "Tipo de incidente (malware, breach, dos, suspicious-activity)");
            var incidentTargetOption = new Option<string>("--target", "Alvo do incidente (IP, hostname)") { IsRequired = true };
            var incidentActionOption = new Option<string[]>("--actions", () => new[] { "isolate", "collect", "analyze" }, "Ações a executar");
            var incidentOutputOption = new Option<string?>("--output", "Diretório de saída dos artefatos");

            incidentCommand.AddArgument(incidentTypeArgument);
            incidentCommand.AddOption(incidentTargetOption);
            incidentCommand.AddOption(incidentActionOption);
            incidentCommand.AddOption(incidentOutputOption);

            incidentCommand.SetHandler(async (type, target, actions, output) =>
            {
                await ExecuteIncidentResponse(type, target, actions, output);
            }, incidentTypeArgument, incidentTargetOption, incidentActionOption, incidentOutputOption);

            defenseCommand.AddCommand(incidentCommand);
        }

        private async Task ExecuteNetworkMonitoring(string network, int interval, string? alertsFile, string? baselineFile)
        {
            _logger.LogInformation("Iniciando monitoramento de rede: {Network}", network);

            var hostDiscoverer = _serviceProvider.GetRequiredService<HostDiscoverer>();
            var portScanner = _serviceProvider.GetRequiredService<PortScanner>();

            NetworkBaseline? baseline = null;
            if (!string.IsNullOrEmpty(baselineFile) && File.Exists(baselineFile))
            {
                var baselineJson = await File.ReadAllTextAsync(baselineFile);
                baseline = System.Text.Json.JsonSerializer.Deserialize<NetworkBaseline>(baselineJson);
                Console.WriteLine($"[*] Baseline carregado: {baseline?.Hosts.Count} hosts conhecidos");
            }

            var alerts = new List<SecurityAlert>();
            var monitoringStartTime = DateTime.Now;

            Console.WriteLine($"[*] Iniciando monitoramento contínuo da rede {network}");
            Console.WriteLine($"[*] Intervalo: {interval} segundos");
            Console.WriteLine($"[*] Pressione Ctrl+C para parar");

            try
            {
                while (true)
                {
                    Console.WriteLine($"\n[*] {DateTime.Now:HH:mm:ss} - Executando varredura...");

                    // Discover hosts
                    var currentHosts = await hostDiscoverer.DiscoverHostsAsync(
                        network,
                        CancellationToken.None,
                        null,
                        1000,
                        20);

                    // Check for new hosts (potential rogue devices)
                    if (baseline != null)
                    {
                        var newHosts = currentHosts.Where(h => 
                            !baseline.Hosts.Any(bh => bh.IpAddress == h.IpAddress)).ToList();

                        foreach (var newHost in newHosts)
                        {
                            var alert = new SecurityAlert
                            {
                                Timestamp = DateTime.Now,
                                Type = "New Device Detected",
                                Severity = "Medium",
                                Source = newHost.IpAddress,
                                Description = $"Novo dispositivo detectado na rede: {newHost.IpAddress}",
                                Recommendation = "Verificar se o dispositivo é autorizado"
                            };

                            alerts.Add(alert);
                            Console.WriteLine($"[!] ALERTA: {alert.Description}");
                        }
                    }

                    // Quick port scan on active hosts to detect service changes
                    foreach (var host in currentHosts.Take(5)) // Limit to first 5 hosts for performance
                    {
                        var commonPorts = new List<int> { 21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 3389 };
                        var openPorts = await portScanner.ScanPortsAsync(
                            host.IpAddress,
                            commonPorts,
                            CancellationToken.None,
                            null,
                            500,
                            10,
                            false);

                        // Check for suspicious ports
                        var suspiciousPorts = openPorts.Where(p => IsSuspiciousPort(p.Port)).ToList();
                        foreach (var port in suspiciousPorts)
                        {
                            var alert = new SecurityAlert
                            {
                                Timestamp = DateTime.Now,
                                Type = "Suspicious Port Open",
                                Severity = "High",
                                Source = host.IpAddress,
                                Description = $"Porta suspeita aberta: {host.IpAddress}:{port.Port}",
                                Recommendation = "Investigar o serviço executando nesta porta"
                            };

                            alerts.Add(alert);
                            Console.WriteLine($"[!] ALERTA: {alert.Description}");
                        }
                    }

                    Console.WriteLine($"[*] Varredura concluída. {currentHosts.Count} hosts ativos, {alerts.Count} alertas totais");

                    // Save alerts if file specified
                    if (!string.IsNullOrEmpty(alertsFile) && alerts.Any())
                    {
                        var alertsJson = System.Text.Json.JsonSerializer.Serialize(alerts, new System.Text.Json.JsonSerializerOptions
                        {
                            WriteIndented = true
                        });
                        await File.WriteAllTextAsync(alertsFile, alertsJson);
                    }

                    // Wait for next interval
                    await Task.Delay(interval * 1000);
                }
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("\n[*] Monitoramento interrompido pelo usuário");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro durante o monitoramento");
                Console.WriteLine($"[!] Erro: {ex.Message}");
            }

            Console.WriteLine($"[*] Monitoramento finalizado. Total de alertas: {alerts.Count}");
        }

        private async Task ExecuteBaselineCreation(string network, string output, int duration)
        {
            _logger.LogInformation("Criando baseline para rede: {Network}", network);

            var hostDiscoverer = _serviceProvider.GetRequiredService<HostDiscoverer>();
            var portScanner = _serviceProvider.GetRequiredService<PortScanner>();

            Console.WriteLine($"[*] Criando baseline da rede {network}");
            Console.WriteLine($"[*] Duração: {duration} segundos");

            var baseline = new NetworkBaseline
            {
                Network = network,
                CreatedAt = DateTime.Now,
                Hosts = new List<HostResult>()
            };

            try
            {
                // Discover all hosts
                Console.WriteLine("[*] Descobrindo hosts...");
                var hosts = await hostDiscoverer.DiscoverHostsAsync(
                    network,
                    CancellationToken.None,
                    host => Console.WriteLine($"[+] Host encontrado: {host.IpAddress}"),
                    2000,
                    30);

                // Scan common ports on each host
                Console.WriteLine($"[*] Escaneando portas em {hosts.Count} hosts...");
                var commonPorts = new List<int> { 21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 1433, 3306, 3389, 5432 };

                foreach (var host in hosts)
                {
                    Console.WriteLine($"[*] Escaneando {host.IpAddress}...");
                    var openPorts = await portScanner.ScanPortsAsync(
                        host.IpAddress,
                        commonPorts,
                        CancellationToken.None,
                        null,
                        1000,
                        20,
                        true);

                    host.OpenPorts = openPorts;
                    baseline.Hosts.Add(host);
                }

                // Save baseline
                var baselineJson = System.Text.Json.JsonSerializer.Serialize(baseline, new System.Text.Json.JsonSerializerOptions
                {
                    WriteIndented = true
                });
                await File.WriteAllTextAsync(output, baselineJson);

                Console.WriteLine($"[*] Baseline criado com sucesso!");
                Console.WriteLine($"[*] Hosts: {baseline.Hosts.Count}");
                Console.WriteLine($"[*] Total de portas abertas: {baseline.Hosts.Sum(h => h.OpenPorts.Count)}");
                Console.WriteLine($"[*] Salvo em: {output}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao criar baseline");
                Console.WriteLine($"[!] Erro: {ex.Message}");
            }
        }

        private async Task ExecuteLogAnalysis(string logFile, string logType, string? output, string? rulesFile)
        {
            _logger.LogInformation("Analisando arquivo de log: {LogFile}", logFile);

            if (!File.Exists(logFile))
            {
                Console.WriteLine($"[!] Arquivo de log não encontrado: {logFile}");
                return;
            }

            Console.WriteLine($"[*] Analisando logs: {logFile}");
            Console.WriteLine($"[*] Tipo: {logType}");

            var alerts = new List<SecurityAlert>();
            var suspiciousPatterns = GetSuspiciousPatterns(logType);

            try
            {
                var lines = await File.ReadAllLinesAsync(logFile);
                Console.WriteLine($"[*] Processando {lines.Length} linhas...");

                for (int i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];
                    
                    foreach (var pattern in suspiciousPatterns)
                    {
                        if (System.Text.RegularExpressions.Regex.IsMatch(line, pattern.Pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                        {
                            var alert = new SecurityAlert
                            {
                                Timestamp = DateTime.Now,
                                Type = pattern.Type,
                                Severity = pattern.Severity,
                                Source = ExtractSourceFromLog(line, logType),
                                Description = $"Padrão suspeito detectado: {pattern.Description}",
                                Details = line,
                                Recommendation = pattern.Recommendation
                            };

                            alerts.Add(alert);
                            Console.WriteLine($"[!] ALERTA (linha {i + 1}): {alert.Type} - {alert.Description}");
                        }
                    }
                }

                Console.WriteLine($"\n[*] Análise concluída. {alerts.Count} alertas encontrados.");

                // Group alerts by type
                var alertGroups = alerts.GroupBy(a => a.Type).ToList();
                foreach (var group in alertGroups)
                {
                    Console.WriteLine($"  - {group.Key}: {group.Count()} ocorrências");
                }

                // Save alerts if output specified
                if (!string.IsNullOrEmpty(output))
                {
                    var alertsJson = System.Text.Json.JsonSerializer.Serialize(alerts, new System.Text.Json.JsonSerializerOptions
                    {
                        WriteIndented = true
                    });
                    await File.WriteAllTextAsync(output, alertsJson);
                    Console.WriteLine($"[*] Alertas salvos em: {output}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro durante análise de logs");
                Console.WriteLine($"[!] Erro: {ex.Message}");
            }
        }

        private async Task ExecuteThreatHunting(string network, string[] threats, string? output, bool deep)
        {
            _logger.LogInformation("Iniciando threat hunting na rede: {Network}", network);

            Console.WriteLine($"[*] Iniciando busca por ameaças na rede {network}");
            Console.WriteLine($"[*] Ameaças: {string.Join(", ", threats)}");
            Console.WriteLine($"[*] Modo: {(deep ? "Profundo" : "Rápido")}");

            var findings = new List<ThreatFinding>();

            try
            {
                var hostDiscoverer = _serviceProvider.GetRequiredService<HostDiscoverer>();
                var portScanner = _serviceProvider.GetRequiredService<PortScanner>();

                // Discover hosts
                Console.WriteLine("[*] Descobrindo hosts...");
                var hosts = await hostDiscoverer.DiscoverHostsAsync(network, CancellationToken.None, null, 1000, 30);

                foreach (var host in hosts)
                {
                    Console.WriteLine($"[*] Analisando {host.IpAddress}...");

                    // Check for malware indicators
                    if (threats.Contains("malware"))
                    {
                        var malwareFindings = await CheckMalwareIndicators(host.IpAddress, deep);
                        findings.AddRange(malwareFindings);
                    }

                    // Check for backdoors
                    if (threats.Contains("backdoors"))
                    {
                        var backdoorFindings = await CheckBackdoorIndicators(host.IpAddress, portScanner, deep);
                        findings.AddRange(backdoorFindings);
                    }

                    // Check for lateral movement
                    if (threats.Contains("lateral-movement"))
                    {
                        var lateralFindings = await CheckLateralMovementIndicators(host.IpAddress, portScanner);
                        findings.AddRange(lateralFindings);
                    }
                }

                Console.WriteLine($"\n[*] Threat hunting concluído. {findings.Count} indicadores encontrados.");

                foreach (var finding in findings.Take(10))
                {
                    Console.WriteLine($"[!] {finding.ThreatType} - {finding.Indicator}");
                    Console.WriteLine($"    Host: {finding.Host}");
                    Console.WriteLine($"    Confiança: {finding.Confidence}");
                }

                if (findings.Count > 10)
                {
                    Console.WriteLine($"[*] ... e mais {findings.Count - 10} indicadores.");
                }

                // Save findings if output specified
                if (!string.IsNullOrEmpty(output))
                {
                    var findingsJson = System.Text.Json.JsonSerializer.Serialize(findings, new System.Text.Json.JsonSerializerOptions
                    {
                        WriteIndented = true
                    });
                    await File.WriteAllTextAsync(output, findingsJson);
                    Console.WriteLine($"[*] Resultados salvos em: {output}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro durante threat hunting");
                Console.WriteLine($"[!] Erro: {ex.Message}");
            }
        }

        private async Task ExecuteIncidentResponse(string type, string target, string[] actions, string? outputDir)
        {
            _logger.LogInformation("Iniciando resposta a incidente: {Type} em {Target}", type, target);

            Console.WriteLine($"[*] Respondendo a incidente: {type}");
            Console.WriteLine($"[*] Alvo: {target}");
            Console.WriteLine($"[*] Ações: {string.Join(", ", actions)}");

            var artifacts = new List<string>();

            try
            {
                if (!string.IsNullOrEmpty(outputDir))
                {
                    Directory.CreateDirectory(outputDir);
                }

                foreach (var action in actions)
                {
                    Console.WriteLine($"\n[*] Executando ação: {action}");

                    switch (action.ToLower())
                    {
                        case "isolate":
                            await ExecuteIsolation(target);
                            break;

                        case "collect":
                            var collectedArtifacts = await ExecuteArtifactCollection(target, outputDir);
                            artifacts.AddRange(collectedArtifacts);
                            break;

                        case "analyze":
                            await ExecuteQuickAnalysis(target, type);
                            break;

                        default:
                            Console.WriteLine($"[!] Ação desconhecida: {action}");
                            break;
                    }
                }

                Console.WriteLine($"\n[*] Resposta a incidente concluída.");
                if (artifacts.Any())
                {
                    Console.WriteLine($"[*] Artefatos coletados: {artifacts.Count}");
                    foreach (var artifact in artifacts)
                    {
                        Console.WriteLine($"  - {artifact}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro durante resposta a incidente");
                Console.WriteLine($"[!] Erro: {ex.Message}");
            }
        }

        // Helper methods
        private bool IsSuspiciousPort(int port)
        {
            // Common backdoor/malware ports
            var suspiciousPorts = new[] { 1234, 1337, 4444, 5555, 6666, 7777, 8888, 9999, 12345, 31337 };
            return suspiciousPorts.Contains(port);
        }

        private List<SuspiciousPattern> GetSuspiciousPatterns(string logType)
        {
            var patterns = new List<SuspiciousPattern>();

            // Common patterns for all log types
            patterns.AddRange(new[]
            {
                new SuspiciousPattern
                {
                    Pattern = @"(failed|invalid|unauthorized|denied).*login",
                    Type = "Failed Login",
                    Severity = "Medium",
                    Description = "Tentativa de login falhada",
                    Recommendation = "Verificar se é um ataque de força bruta"
                },
                new SuspiciousPattern
                {
                    Pattern = @"(\d{1,3}\.){3}\d{1,3}.*(\.\./|\.\.\\)",
                    Type = "Directory Traversal",
                    Severity = "High",
                    Description = "Tentativa de directory traversal",
                    Recommendation = "Bloquear IP e verificar vulnerabilidades"
                },
                new SuspiciousPattern
                {
                    Pattern = @"(union|select|insert|delete|drop|exec|script)",
                    Type = "SQL Injection",
                    Severity = "High",
                    Description = "Possível tentativa de SQL injection",
                    Recommendation = "Verificar aplicação e implementar WAF"
                }
            });

            // Log type specific patterns
            if (logType.ToLower().Contains("apache") || logType.ToLower().Contains("nginx"))
            {
                patterns.Add(new SuspiciousPattern
                {
                    Pattern = @"HTTP/1\.[01]"" (4\d{2}|5\d{2})",
                    Type = "HTTP Error",
                    Severity = "Low",
                    Description = "Erro HTTP suspeito",
                    Recommendation = "Verificar se é scanning automatizado"
                });
            }

            return patterns;
        }

        private string ExtractSourceFromLog(string line, string logType)
        {
            // Simple IP extraction
            var ipPattern = @"(\d{1,3}\.){3}\d{1,3}";
            var match = System.Text.RegularExpressions.Regex.Match(line, ipPattern);
            return match.Success ? match.Value : "Unknown";
        }

        private async Task<List<ThreatFinding>> CheckMalwareIndicators(string host, bool deep)
        {
            var findings = new List<ThreatFinding>();

            // Simulate malware checks (in real implementation, this would check various indicators)
            await Task.Delay(deep ? 2000 : 500);

            // Example: Check for suspicious network connections
            // This is a placeholder - real implementation would use actual malware detection logic
            
            return findings;
        }

        private async Task<List<ThreatFinding>> CheckBackdoorIndicators(string host, PortScanner portScanner, bool deep)
        {
            var findings = new List<ThreatFinding>();

            // Check for backdoor ports
            var backdoorPorts = new List<int> { 1234, 1337, 4444, 5555, 6666, 7777, 8888, 9999, 12345, 31337 };
            var openPorts = await portScanner.ScanPortsAsync(host, backdoorPorts, CancellationToken.None, null, 1000, 10, false);

            foreach (var port in openPorts)
            {
                findings.Add(new ThreatFinding
                {
                    Host = host,
                    ThreatType = "Backdoor",
                    Indicator = $"Porta suspeita aberta: {port.Port}",
                    Confidence = "Medium",
                    Timestamp = DateTime.Now
                });
            }

            return findings;
        }

        private async Task<List<ThreatFinding>> CheckLateralMovementIndicators(string host, PortScanner portScanner)
        {
            var findings = new List<ThreatFinding>();

            // Check for lateral movement indicators (SMB, RDP, WinRM, etc.)
            var lateralPorts = new List<int> { 135, 139, 445, 3389, 5985, 5986 };
            var openPorts = await portScanner.ScanPortsAsync(host, lateralPorts, CancellationToken.None, null, 1000, 10, false);

            if (openPorts.Count >= 3)
            {
                findings.Add(new ThreatFinding
                {
                    Host = host,
                    ThreatType = "Lateral Movement",
                    Indicator = "Múltiplas portas de administração abertas",
                    Confidence = "Low",
                    Timestamp = DateTime.Now
                });
            }

            return findings;
        }

        private async Task ExecuteIsolation(string target)
        {
            Console.WriteLine($"[*] Simulando isolamento de {target}");
            Console.WriteLine("    - Bloqueando tráfego de rede");
            Console.WriteLine("    - Removendo acesso remoto");
            Console.WriteLine("    - Notificando administradores");
            await Task.Delay(1000);
            Console.WriteLine("[+] Isolamento concluído");
        }

        private async Task<List<string>> ExecuteArtifactCollection(string target, string? outputDir)
        {
            var artifacts = new List<string>();
            
            Console.WriteLine($"[*] Coletando artefatos de {target}");
            
            if (!string.IsNullOrEmpty(outputDir))
            {
                // Simulate artifact collection
                var artifactFiles = new[]
                {
                    "network_connections.txt",
                    "running_processes.txt",
                    "system_logs.txt",
                    "file_hashes.txt"
                };

                foreach (var artifact in artifactFiles)
                {
                    var filePath = Path.Combine(outputDir, artifact);
                    await File.WriteAllTextAsync(filePath, $"Artefato coletado de {target} em {DateTime.Now}");
                    artifacts.Add(filePath);
                    Console.WriteLine($"    + {artifact}");
                }
            }

            return artifacts;
        }

        private async Task ExecuteQuickAnalysis(string target, string incidentType)
        {
            Console.WriteLine($"[*] Executando análise rápida para {incidentType} em {target}");
            
            await Task.Delay(2000);
            
            Console.WriteLine("    - Verificando indicadores de comprometimento");
            Console.WriteLine("    - Analisando conexões de rede");
            Console.WriteLine("    - Verificando processos suspeitos");
            Console.WriteLine("[+] Análise concluída");
        }
    }

    // Supporting classes
    public class NetworkBaseline
    {
        public string Network { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public List<HostResult> Hosts { get; set; } = new();
    }

    public class SecurityAlert
    {
        public DateTime Timestamp { get; set; }
        public string Type { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string? Details { get; set; }
        public string? Recommendation { get; set; }
    }

    public class SuspiciousPattern
    {
        public string Pattern { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Recommendation { get; set; } = string.Empty;
    }

    public class ThreatFinding
    {
        public string Host { get; set; } = string.Empty;
        public string ThreatType { get; set; } = string.Empty;
        public string Indicator { get; set; } = string.Empty;
        public string Confidence { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
    }
}

