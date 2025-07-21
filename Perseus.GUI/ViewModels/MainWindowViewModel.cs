using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.ObjectModel;
using System.Windows.Input;
using Perseus.GUI.Models;

namespace Perseus.GUI.ViewModels;

public class MainWindowViewModel : ViewModelBase
{
    private readonly IServiceProvider _serviceProvider;
    private ViewModelBase _currentView;
    private string _statusMessage = "Pronto";
    private bool _isOperationRunning = false;

    public MainWindowViewModel(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
        
        // Initialize navigation items
        NavigationItems = new ObservableCollection<NavigationItem>
        {
            new NavigationItem { Name = "Attack", Icon = "🔴", Description = "Modo Red Team - Operações Ofensivas" },
            new NavigationItem { Name = "Defense", Icon = "🛡️", Description = "Modo Blue Team - Operações Defensivas" },
            new NavigationItem { Name = "Settings", Icon = "⚙️", Description = "Configurações e Preferências" }
        };

        // Set default view
        _currentView = _serviceProvider.GetRequiredService<AttackViewModel>();

        // Initialize commands
        NavigateCommand = new RelayCommand<string>(Navigate);
        ExitCommand = new RelayCommand(Exit);
    }

    public ObservableCollection<NavigationItem> NavigationItems { get; }

    public ViewModelBase CurrentView
    {
        get => _currentView;
        set => SetField(ref _currentView, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetField(ref _statusMessage, value);
    }

    public bool IsOperationRunning
    {
        get => _isOperationRunning;
        set => SetField(ref _isOperationRunning, value);
    }

    public ICommand NavigateCommand { get; }
    public ICommand ExitCommand { get; }

    private void Navigate(string? viewName)
    {
        if (string.IsNullOrEmpty(viewName)) return;

        CurrentView = viewName switch
        {
            "Attack" => _serviceProvider.GetRequiredService<AttackViewModel>(),
            "Defense" => _serviceProvider.GetRequiredService<DefenseViewModel>(),
            "Settings" => _serviceProvider.GetRequiredService<SettingsViewModel>(),
            _ => CurrentView
        };

        StatusMessage = $"Navegado para {viewName}";
    }

    private void Exit()
    {
        Environment.Exit(0);
    }

    public void UpdateStatus(string message)
    {
        StatusMessage = message;
    }

    public void SetOperationRunning(bool isRunning)
    {
        IsOperationRunning = isRunning;
    }
}

public class RelayCommand : ICommand
{
    private readonly Action _execute;
    private readonly Func<bool>? _canExecute;

    public RelayCommand(Action execute, Func<bool>? canExecute = null)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter) => _canExecute?.Invoke() ?? true;

    public void Execute(object? parameter) => _execute();

    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

public class RelayCommand<T> : ICommand
{
    private readonly Action<T?> _execute;
    private readonly Func<T?, bool>? _canExecute;

    public RelayCommand(Action<T?> execute, Func<T?, bool>? canExecute = null)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter) => _canExecute?.Invoke((T?)parameter) ?? true;

    public void Execute(object? parameter) => _execute((T?)parameter);

    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

