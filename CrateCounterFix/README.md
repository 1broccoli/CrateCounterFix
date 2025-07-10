# Drive Zone Online - Crate Counter Fix (Android)

## 🎯 Problem Solved
**FIXED: 300/100 = 3 cars, not 1 car (proper reward calculation)**

The original issue was that when crate counters exceeded certain thresholds, players would only receive 1 car instead of the expected multiple cars based on complete cycles.

## 🚀 Quick Start

### For Android Devices
```bash
# Using Python controller (recommended)
python crate_counter_controller.py

# Or direct Frida injection
frida -U -f com.drivezone.package -l crate_counter_reset.js --no-pause

# Or attach to running process
frida -U "Drive Zone Online" -l crate_counter_reset.js
```

### For Windows (Batch Script)
```cmd
run_crate_reset.bat
```

## 📁 Files in this Directory

### Main Scripts
- **`crate_counter_reset.js`** - Main Frida script with Android support and 100-cycle logic
- **`crate_counter_controller.py`** - Python controller for easy script management
- **`run_crate_reset.bat`** - Windows batch script for quick execution

### Specialized Scripts
- **`gameguardian_pattern_hook.js`** - Specialized GameGuardian pattern monitoring
- **`test_gameguardian_pattern.js`** - Test/validation script for pattern detection
- **`advanced_crate_reset.js`** - Advanced version with additional features

### Backup & Documentation
- **`crate_counter_reset_fixed.js`** - Backup of working version
- **`ANDROID_FIX_SUMMARY.md`** - Detailed technical documentation

## 🔧 How It Works

1. **Pattern Detection:** Monitors GameGuardian pattern `1,514Q;200~80000Q;1,514Q;200~80000::25`
2. **Counter Monitoring:** Watches counter values at pattern offsets +4 and +12
3. **Reward Calculation:** When counter ≥ 100, calculates `completeCycles = floor(value/100)`
4. **Counter Reset:** Resets counter to `remainder = value % 100`
5. **Reward Hook:** Intercepts reward methods to return calculated number of cars

## 📊 Expected Results

| Crate Count | Old Result | New Result (Fixed) |
|-------------|------------|-------------------|
| 300 crates  | 1 car      | **3 cars**        |
| 450 crates  | 1 car      | **4 cars** (50 remaining) |
| 150 crates  | 1 car      | **1 car** (50 remaining) |
| 99 crates   | 0 cars     | **0 cars** (wait for next) |

## 🎮 Available Commands

When using the Python controller:
- `reset` - Manually reset crate counter
- `scan` - Scan for counter memory locations
- `pattern` - Search for GameGuardian pattern
- `status` - Check current counter values
- `help` - Show available commands

## 🔍 GameGuardian Pattern

The fix works specifically with the GameGuardian search pattern:
```
1,514Q;200~80000Q;1,514Q;200~80000::25
```

This pattern represents:
- `1514` - Static identifier values
- `200~80000` - Counter values (the ones we modify)
- `::25` - Search configuration

## 🛠️ Technical Details

### Counter Calculation Logic
- **Old:** Counter reset at 160 with inconsistent rewards
- **New:** Counter reset at 100 with proper cycle-based rewards
- **Formula:** `completeCycles = Math.floor(currentValue / 100)`

### Android Compatibility
- Added support for `libil2cpp.so` module (Android IL2CPP)
- Multiple module detection: `["GameAssembly.dll", "libil2cpp.so", "libunity.so", "libgame.so"]`
- Android-specific export enumeration

### Spin Value Handling
- Monitors spin values (30/29) that are added to counters
- Prevents overflow by adjusting spin values when they would exceed 100
- Preserves proper reward calculation during spin operations

## 🔒 Safety Notes

- **Backup your save data** before experimenting
- **USB debugging** must be enabled for Android devices
- **Use at your own risk** - may affect game stability
- **Online play** - modifications may be detected
- **Updates** - hooks may need adjustment after game updates

## 📱 Android Requirements

1. **Android device** with Drive Zone Online installed
2. **USB debugging** enabled in Developer Options
3. **Frida** installed on your computer
4. **ADB** connection to the device

## 🆘 Troubleshooting

### Common Issues
- **Pattern not found:** Try rescanning with `pattern` command
- **No rewards:** Check if GameGuardian pattern is active in memory
- **Counter not resetting:** Manually trigger with `reset` command

### Debug Information
The script provides detailed logging:
```
[*] Found GameGuardian pattern at: 0x12345678
[*] Counter reached limit - val2: 300, val4: 150
[*] Complete cycles: 3, remainder: 0
[*] Calculated reward: 3 cars
```

## 🎉 Success Story

With this fix, players who previously got stuck with 1 car rewards when their counter exceeded limits now receive the proper number of cars based on complete cycles. The fix maintains game balance while ensuring fair reward distribution.

---

**Happy gaming! 🎮**
