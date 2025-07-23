using CommunityToolkit.Mvvm.ComponentModel;

namespace Perseus.GUI.ViewModels;

public partial class MainWindowViewModel : ViewModelBase
{
    [ObservableProperty]
    private ViewModelBase _currentViewModel;

    [ObservableProperty]
    private string _selectedTab = "Attack";

    public AttackViewModel AttackViewModel { get; }
    public DefenseViewModel DefenseViewModel { get; }

    public MainWindowViewModel()
    {
        AttackViewModel = new AttackViewModel();
        DefenseViewModel = new DefenseViewModel();
        _currentViewModel = AttackViewModel;
    }

    partial void OnSelectedTabChanged(string value)
    {
        CurrentViewModel = value switch
        {
            "Attack" => AttackViewModel,
            "Defense" => DefenseViewModel,
            _ => AttackViewModel
        };
    }
}
