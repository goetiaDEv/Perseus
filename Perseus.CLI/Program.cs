using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Perseus.CLI.Commands;
using Perseus.Core.Network;
using Perseus.Core.Vulnerability;

namespace Perseus.CLI
{
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            // Setup dependency injection
            var services = new ServiceCollection();
            ConfigureServices(services);
            var serviceProvider = services.BuildServiceProvider();

            // Create root command
            var rootCommand = new RootCommand("Perseus - Ferramenta de Cybersecurity para Red Team e Blue Team")
            {
                Name = "perseus"
            };

            // Add global options
            var verboseOption = new Option<bool>(
                aliases: new[] { "--verbose", "-v" },
                description: "Habilitar saída detalhada");

            var outputOption = new Option<string?>(
                aliases: new[] { "--output", "-o" },
                description: "Arquivo de saída para os resultados");

            rootCommand.AddGlobalOption(verboseOption);
            rootCommand.AddGlobalOption(outputOption);

            // Create command handlers
            var attackCommands = new AttackCommands(serviceProvider);
            var defenseCommands = new DefenseCommands(serviceProvider);

            // Add attack mode commands
            var attackCommand = new Command("attack", "Modo de operação ofensiva (Red Team)");
            attackCommands.ConfigureCommands(attackCommand);
            rootCommand.AddCommand(attackCommand);

            // Add defense mode commands
            var defenseCommand = new Command("defense", "Modo de operação defensiva (Blue Team)");
            defenseCommands.ConfigureCommands(defenseCommand);
            rootCommand.AddCommand(defenseCommand);

            // Add utility commands
            var utilityCommands = new UtilityCommands(serviceProvider);
            utilityCommands.ConfigureCommands(rootCommand);

            return await rootCommand.InvokeAsync(args);
        }

        private static void ConfigureServices(ServiceCollection services)
        {
            // Logging
            services.AddLogging(builder =>
            {
                builder.AddConsole();
                builder.SetMinimumLevel(LogLevel.Information);
            });

            // HTTP Client
            services.AddHttpClient();

            // Core services
            services.AddTransient<HostDiscoverer>();
            services.AddTransient<PortScanner>();
            services.AddTransient<BannerGrabber>();
            services.AddTransient<CveChecker>();

            // Command handlers
            services.AddTransient<AttackCommands>();
            services.AddTransient<DefenseCommands>();
            services.AddTransient<UtilityCommands>();
        }
    }
}

