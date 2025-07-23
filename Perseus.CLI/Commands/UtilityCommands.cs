using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Perseus.Core.Network;

namespace Perseus.CLI.Commands
{
    public class UtilityCommands
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<UtilityCommands> _logger;

        public UtilityCommands(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
            _logger = serviceProvider.GetRequiredService<ILogger<UtilityCommands>>();
        }

        public void ConfigureCommands(Command rootCommand)
        {
            // Version command
            var versionCommand = new Command("version", "Exibir informações de versão");
            versionCommand.SetHandler(() =>
            {
                Console.WriteLine("Perseus Security Scanner v1.0.0");
                Console.WriteLine("Ferramenta de Cybersecurity para Red Team e Blue Team");
                Console.WriteLine("Desenvolvido com base no Helius e filosofia SKEF");
                Console.WriteLine();
                Console.WriteLine("Autor: Manus AI");
                Console.WriteLine("Data: 2025");
            });
            rootCommand.AddCommand(versionCommand);

            // Help command for modes
            var helpCommand = new Command("help-modes", "Exibir ajuda sobre os modos de operação");
            helpCommand.SetHandler(() =>
            {
                Console.WriteLine("=== MODOS DE OPERAÇÃO DO PERSEUS ===");
                Console.WriteLine();
                Console.WriteLine("MODO ATTACK (Red Team):");
                Console.WriteLine("  perseus attack discover <target>     - Descobrir hosts ativos");
                Console.WriteLine("  perseus attack scan <host>           - Escanear portas");
                Console.WriteLine("  perseus attack vuln <host>           - Avaliar vulnerabilidades");
                Console.WriteLine("  perseus attack full <target>         - Avaliação completa");
                Console.WriteLine();
                Console.WriteLine("MODO DEFENSE (Blue Team):");
                Console.WriteLine("  perseus defense monitor <network>    - Monitorar rede");
                Console.WriteLine("  perseus defense baseline <network>   - Criar baseline");
                Console.WriteLine("  perseus defense logs <logfile>       - Analisar logs");
                Console.WriteLine("  perseus defense hunt <network>       - Threat hunting");
                Console.WriteLine("  perseus defense incident <type>      - Resposta a incidentes");
                Console.WriteLine();
                Console.WriteLine("UTILITÁRIOS:");
                Console.WriteLine("  perseus version                      - Informações de versão");
                Console.WriteLine("  perseus help-modes                   - Esta ajuda");
                Console.WriteLine("  perseus examples                     - Exemplos de uso");
                Console.WriteLine();
                Console.WriteLine("Use 'perseus <comando> --help' para ajuda específica de cada comando.");
            });
            rootCommand.AddCommand(helpCommand);

            // Examples command
            var examplesCommand = new Command("examples", "Exibir exemplos de uso");
            examplesCommand.SetHandler(() =>
            {
                Console.WriteLine("=== EXEMPLOS DE USO DO PERSEUS ===");
                Console.WriteLine();
                Console.WriteLine("RED TEAM (Modo Attack):");
                Console.WriteLine();
                Console.WriteLine("1. Descoberta básica de hosts:");
                Console.WriteLine("   perseus attack discover 192.168.1.0/24");
                Console.WriteLine();
                Console.WriteLine("2. Varredura de portas com captura de banner:");
                Console.WriteLine("   perseus attack scan 192.168.1.100 --ports 1-1000 --banner");
                Console.WriteLine();
                Console.WriteLine("3. Avaliação de vulnerabilidades (CVSS >= 7.0):");
                Console.WriteLine("   perseus attack vuln 192.168.1.100 --min-cvss 7.0");
                Console.WriteLine();
                Console.WriteLine("4. Avaliação completa em modo stealth:");
                Console.WriteLine("   perseus attack full 192.168.1.0/24 --stealth --output results.json");
                Console.WriteLine();
                Console.WriteLine("BLUE TEAM (Modo Defense):");
                Console.WriteLine();
                Console.WriteLine("1. Criar baseline da rede:");
                Console.WriteLine("   perseus defense baseline 192.168.1.0/24 --output baseline.json");
                Console.WriteLine();
                Console.WriteLine("2. Monitoramento contínuo com baseline:");
                Console.WriteLine("   perseus defense monitor 192.168.1.0/24 --baseline baseline.json --alerts alerts.json");
                Console.WriteLine();
                Console.WriteLine("3. Análise de logs do Apache:");
                Console.WriteLine("   perseus defense logs /var/log/apache2/access.log --type apache --output alerts.json");
                Console.WriteLine();
                Console.WriteLine("4. Threat hunting para malware e backdoors:");
                Console.WriteLine("   perseus defense hunt 192.168.1.0/24 --threats malware backdoors --deep");
                Console.WriteLine();
                Console.WriteLine("5. Resposta a incidente de malware:");
                Console.WriteLine("   perseus defense incident malware --target 192.168.1.100 --actions isolate collect analyze");
                Console.WriteLine();
                Console.WriteLine("COMBINAÇÕES AVANÇADAS:");
                Console.WriteLine();
                Console.WriteLine("1. Red Team: Avaliação completa com relatório:");
                Console.WriteLine("   perseus attack full 10.0.0.0/24 --ports 1-65535 --min-cvss 4.0 --output pentest_results.json");
                Console.WriteLine();
                Console.WriteLine("2. Blue Team: Monitoramento com threat hunting:");
                Console.WriteLine("   perseus defense monitor 192.168.1.0/24 --interval 300 &");
                Console.WriteLine("   perseus defense hunt 192.168.1.0/24 --threats lateral-movement --output hunt_results.json");
            });
            rootCommand.AddCommand(examplesCommand);

            // Configuration command
            var configCommand = new Command("config", "Gerenciar configurações do Perseus");
            
            var showConfigCommand = new Command("show", "Exibir configuração atual");
            showConfigCommand.SetHandler(() =>
            {
                Console.WriteLine("=== CONFIGURAÇÃO ATUAL DO PERSEUS ===");
                Console.WriteLine();
                Console.WriteLine("Timeouts padrão:");
                Console.WriteLine("  - Ping: 1000ms");
                Console.WriteLine("  - Port scan: 1000ms");
                Console.WriteLine("  - Banner grab: 3000ms");
                Console.WriteLine();
                Console.WriteLine("Concorrência padrão:");
                Console.WriteLine("  - Host discovery: 50 threads");
                Console.WriteLine("  - Port scanning: 100 threads");
                Console.WriteLine();
                Console.WriteLine("APIs configuradas:");
                Console.WriteLine("  - NVD CVE Database: Habilitado");
                Console.WriteLine("  - Local CVE Database: Habilitado");
                Console.WriteLine();
                Console.WriteLine("Formatos de saída suportados:");
                Console.WriteLine("  - JSON");
                Console.WriteLine("  - Markdown (em desenvolvimento)");
                Console.WriteLine("  - HTML (em desenvolvimento)");
                Console.WriteLine("  - PDF (em desenvolvimento)");
            });
            
            configCommand.AddCommand(showConfigCommand);
            rootCommand.AddCommand(configCommand);

            // Test command for connectivity
            var testCommand = new Command("test", "Testar conectividade e funcionalidades");
            
            var testConnectivityCommand = new Command("connectivity", "Testar conectividade de rede");
            var testTargetArgument = new Argument<string>("target", "Alvo para testar (IP ou hostname)");
            testConnectivityCommand.AddArgument(testTargetArgument);
            
            testConnectivityCommand.SetHandler(async (target) =>
            {
                await TestConnectivity(target);
            }, testTargetArgument);
            
            var testCveCommand = new Command("cve", "Testar conectividade com APIs de CVE");
            testCveCommand.SetHandler(async () =>
            {
                await TestCveConnectivity();
            });
            
            testCommand.AddCommand(testConnectivityCommand);
            testCommand.AddCommand(testCveCommand);
            rootCommand.AddCommand(testCommand);
        }

        private async Task TestConnectivity(string target)
        {
            Console.WriteLine($"[*] Testando conectividade com {target}");
            
            try
            {
                var hostDiscoverer = _serviceProvider.GetRequiredService<HostDiscoverer>();
                
                Console.WriteLine("[*] Testando ping...");
                var hosts = await hostDiscoverer.DiscoverHostsFromListAsync(
                    new List<string> { target },
                    CancellationToken.None,
                    null,
                    2000,
                    1);
                
                if (hosts.Any() && hosts[0].IsAlive)
                {
                    Console.WriteLine($"[+] Ping bem-sucedido para {target}");
                    if (!string.IsNullOrEmpty(hosts[0].Hostname))
                    {
                        Console.WriteLine($"[+] Hostname: {hosts[0].Hostname}");
                    }
                }
                else
                {
                    Console.WriteLine($"[-] Ping falhou para {target}");
                }
                
                Console.WriteLine("[*] Testando varredura de porta...");
                var portScanner = _serviceProvider.GetRequiredService<PortScanner>();
                var openPorts = await portScanner.ScanPortsAsync(
                    target,
                    new List<int> { 80, 443, 22, 21 },
                    CancellationToken.None,
                    null,
                    2000,
                    4,
                    false);
                
                if (openPorts.Any())
                {
                    Console.WriteLine($"[+] Portas abertas encontradas: {string.Join(", ", openPorts.Select(p => p.Port))}");
                }
                else
                {
                    Console.WriteLine("[-] Nenhuma porta aberta encontrada nas portas testadas");
                }
                
                Console.WriteLine("[+] Teste de conectividade concluído");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Erro durante teste de conectividade: {ex.Message}");
            }
        }

        private async Task TestCveConnectivity()
        {
            Console.WriteLine("[*] Testando conectividade com APIs de CVE");
            
            try
            {
                var httpClient = _serviceProvider.GetRequiredService<HttpClient>();
                
                Console.WriteLine("[*] Testando NVD API...");
                var response = await httpClient.GetAsync("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1");
                
                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine("[+] NVD API acessível");
                    var content = await response.Content.ReadAsStringAsync();
                    if (content.Contains("vulnerabilities"))
                    {
                        Console.WriteLine("[+] Resposta da NVD API válida");
                    }
                }
                else
                {
                    Console.WriteLine($"[-] NVD API retornou status: {response.StatusCode}");
                }
                
                Console.WriteLine("[*] Testando conectividade geral com internet...");
                var testResponse = await httpClient.GetAsync("https://www.google.com");
                if (testResponse.IsSuccessStatusCode)
                {
                    Console.WriteLine("[+] Conectividade com internet OK");
                }
                else
                {
                    Console.WriteLine("[-] Problemas de conectividade com internet");
                }
                
                Console.WriteLine("[+] Teste de APIs concluído");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Erro durante teste de APIs: {ex.Message}");
            }
        }
    }
}

