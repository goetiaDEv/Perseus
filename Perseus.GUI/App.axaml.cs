using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Perseus.Core.Network;
using Perseus.Core.Vulnerability;
using Perseus.GUI.ViewModels;
using Perseus.GUI.Views;
using System;
using System.Net.Http;

namespace Perseus.GUI;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var services = new ServiceCollection();
            ConfigureServices(services);
            var serviceProvider = services.BuildServiceProvider();

            var mainWindow = new MainWindow
            {
                DataContext = serviceProvider.GetRequiredService<MainWindowViewModel>()
            };

            desktop.MainWindow = mainWindow;
        }

        base.OnFrameworkInitializationCompleted();
    }

    private void ConfigureServices(IServiceCollection services)
    {
        // Logging
        services.AddLogging(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Information);
        });

        // HTTP Client
        services.AddSingleton<HttpClient>();

        // Core services
        services.AddSingleton<HostDiscoverer>();
        services.AddSingleton<PortScanner>();
        services.AddSingleton<BannerGrabber>();
        services.AddSingleton<CveChecker>();

        // ViewModels
        services.AddTransient<MainWindowViewModel>();
        services.AddTransient<AttackViewModel>();
        services.AddTransient<DefenseViewModel>();
        services.AddTransient<SettingsViewModel>();
    }
}

