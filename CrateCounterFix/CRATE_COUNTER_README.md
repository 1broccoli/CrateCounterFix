# Drive Zone Online - Crate Counter Reset Scripts

This package contains scripts to fix the crate counter issue in Drive Zone Online where you only get 1 car reward after reaching 160 crates instead of the intended 4 cars.

## Problem Description

In Drive Zone Online, there's a crate counter that shows "x/160" for rewards. When you reach 160 crates, you get 4 cars as rewards. However, if the counter goes beyond 160, you only get 1 car per additional crate. This package provides scripts to automatically reset the counter when it reaches 160 to maintain the 4-car reward structure.

## Files Included

1. **crate_counter_reset.js** - Basic Frida script for counter reset
2. **advanced_crate_reset.js** - Advanced script with IL2CPP targeting
3. **il2cpp_memory_patcher.js** - Direct memory patcher for IL2CPP structures
4. **crate_counter_controller.py** - Python controller for easy management
5. **run_crate_reset.bat** - Windows batch script for easy execution

## Prerequisites

- Python 3.6 or higher
- Frida Tools (`pip install frida-tools`)
- Drive Zone Online running on Android device or emulator
- USB debugging enabled (for Android device)

## Quick Start

### Method 1: Using the Batch Script (Easiest)

1. Make sure Drive Zone Online is running
2. Double-click `run_crate_reset.bat`
3. Follow the on-screen instructions

### Method 2: Using Python Controller

1. Open Command Prompt in the script directory
2. Run: `python crate_counter_controller.py`
3. Choose between Interactive or Monitor mode

### Method 3: Direct Frida Usage

1. Connect your device: `frida -U -l crate_counter_reset.js "Drive Zone Online"`
2. The script will automatically start monitoring

## How It Works

### Basic Approach (crate_counter_reset.js)
- Hooks into UI text updates to detect "x/160" patterns
- Monitors progression system methods
- Resets counter display when it reaches 160
- Modifies reward calculations to ensure 4 cars

### Advanced Approach (advanced_crate_reset.js)
- Targets specific IL2CPP structures found in the game
- Hooks progression widget methods
- Monitors box screen updates
- Provides more reliable counter reset

### Memory Patcher (il2cpp_memory_patcher.js)
- Directly scans and modifies memory values
- Monitors multiple counter addresses
- Provides real-time counter reset
- Most reliable but requires more system resources

## Usage Instructions

### Interactive Mode
When you run the Python controller, you can use these commands:

- `status` - Show current crate count
- `reset` - Manually reset crate counter
- `scan` - Scan for counter memory locations
- `max <number>` - Set maximum count before auto-reset
- `quit` - Exit the program

### Monitor Mode
In monitor mode, the script will:
- Continuously check your crate counter
- Automatically reset it when it reaches 160
- Log all actions to the console

## Configuration Options

You can modify these variables in the scripts:

- `TARGET_COUNTER_VALUE` - When to reset (default: 160)
- `RESET_VALUE` - What to reset to (default: 0)
- `SCAN_INTERVAL` - How often to check (default: 2000ms)

## Safety Features

- **Non-destructive**: Only modifies counter values, not permanent game data
- **Reversible**: Counter resets don't affect your actual progress
- **Minimal impact**: Scripts only target counter-related functions
- **Error handling**: Graceful handling of memory access errors

## Troubleshooting

### Script Not Finding Process
- Make sure Drive Zone Online is running
- Check that USB debugging is enabled
- Try running as administrator

### Counter Not Resetting
- Try the memory patcher script instead
- Use the scan command to find counter locations
- Check that Frida is properly attached

### Getting Only 1 Car After Reset
- The script might need tuning for your game version
- Try manually resetting before claiming rewards
- Use the advanced script for better reliability

## Technical Details

### Game Structure Analysis
The scripts target these IL2CPP structures:
- `Core_UI_ProgressionWithRewardsWidget_Fields`
- `Core_UI_Screens_Boxes_BoxScreen_Fields`
- Counter increment and reward calculation methods

### Memory Patterns
The scripts search for these patterns:
- UI text patterns: "x/160"
- Memory values: 160 (0xA0), 159 (0x9F), etc.
- Method names containing: Counter, Progress, Reward, Box

### Hook Points
Key hook points include:
- TextMeshProUGUI.set_text (UI updates)
- Counter increment methods
- Reward calculation functions
- Box progression widgets

## Example Usage

```bash
# Basic usage
python crate_counter_controller.py

# Direct Frida usage
frida -U -l il2cpp_memory_patcher.js "Drive Zone Online"

# Interactive session
CrateCounter> status
[*] Current crate count: 158/160
CrateCounter> reset
[*] Manual reset completed
```

## Version Compatibility

These scripts are designed for:
- Drive Zone Online (Android)
- IL2CPP-based Unity games
- Frida 16.0+

## Important Notes

⚠️ **Warning**: These scripts modify game memory. Use at your own risk.

- Only use on accounts you don't mind losing
- The scripts are detected by some anti-cheat systems
- Always backup your game progress before use
- Test on a secondary account first

## Support

If you encounter issues:
1. Check that all prerequisites are installed
2. Verify the game is running and accessible
3. Try different script variants
4. Check the console output for error messages

## Contributing

To improve these scripts:
1. Update IL2CPP addresses for new game versions
2. Add support for additional counter types
3. Improve error handling and stability
4. Add new hook points for better reliability

## License

These scripts are provided for educational purposes only. Use responsibly and in accordance with the game's terms of service.
