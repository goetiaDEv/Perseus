using Avalonia.Controls;
using Avalonia.Interactivity;
using Perseus.GUI.ViewModels;

namespace Perseus.GUI.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    private void OnAttackTabClick(object? sender, RoutedEventArgs e)
    {
        if (DataContext is MainWindowViewModel vm)
        {
            vm.SelectedTab = "Attack";
        }
    }

    private void OnDefenseTabClick(object? sender, RoutedEventArgs e)
    {
        if (DataContext is MainWindowViewModel vm)
        {
            vm.SelectedTab = "Defense";
        }
    }
}