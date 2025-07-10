# Drive Zone Online - Android Tools 📱

## 🎯 Crate Counter Fix for Android

**FIXED: 300/100 = 3 cars, not 1 car (proper reward calculation)**

This toolset fixes the crate counter system in Drive Zone Online for Android devices, ensuring players receive the correct number of cars based on complete cycles instead of being limited to 1 car when counters exceed thresholds.

## 📋 Prerequisites

### Android Device Requirements
1. **Android device** with Drive Zone Online installed
2. **USB debugging** enabled in Developer Options
3. **Root access** (recommended but not always required)
4. **Stable USB connection** to computer

### Computer Requirements
1. **Python 3.8+** installed
2. **Frida** installed (`pip install frida-tools frida`)
3. **ADB** (Android Debug Bridge) installed
4. **USB drivers** for your Android device

## 🚀 Quick Setup

### Enable USB Debugging
1. Go to **Settings** → **About phone**
2. Tap **Build number** 7 times to enable Developer Options
3. Go to **Settings** → **Developer options**
4. Enable **USB debugging**
5. Connect device to computer via USB

### Install Frida Server (if needed)
```bash
# Download frida-server for your device architecture
# Push to device and run (requires root)
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

## 🎮 Usage Options

### Option 1: Python Controller (Recommended)
```bash
cd CrateCounterFix
python crate_counter_controller.py
```
- User-friendly interface
- Real-time monitoring
- Interactive commands
- **Best for beginners**

### Option 2: Quick Start Batch
```cmd
cd CrateCounterFix
START_CRATE_FIX.bat
```
- One-click execution
- Windows batch file
- Automatic setup

### Option 3: Direct Frida Injection
```bash
# Spawn new process
frida -U -f com.drivezone.package -l CrateCounterFix/crate_counter_reset.js --no-pause

# Attach to running process
frida -U "Drive Zone Online" -l CrateCounterFix/crate_counter_reset.js
```
- Advanced users only
- Direct script injection
- Manual control

## 📁 CrateCounterFix Folder Contents

### Main Scripts
- **`crate_counter_reset.js`** - Main Frida script with Android support
- **`crate_counter_controller.py`** - Python controller for easy management
- **`START_CRATE_FIX.bat`** - Quick-start batch file for Windows

### Specialized Scripts
- **`gameguardian_pattern_hook.js`** - GameGuardian pattern monitoring
- **`test_gameguardian_pattern.js`** - Pattern validation and testing
- **`advanced_crate_reset.js`** - Advanced features and debugging
- **`run_crate_reset.bat`** - Legacy batch execution

### Documentation
- **`README.md`** - Comprehensive documentation
- **`ANDROID_FIX_SUMMARY.md`** - Technical implementation details

## 🔧 How the Fix Works

### 1. GameGuardian Pattern Detection
The fix monitors the specific GameGuardian pattern:
```
1,514Q;200~80000Q;1,514Q;200~80000::25
```

This pattern represents:
- **1514** - Static identifier values
- **200~80000** - Dynamic counter values (the ones we modify)
- **::25** - Search configuration

### 2. Counter Monitoring
- Watches counter values at pattern offsets `+4` and `+12`
- Triggers when counters reach ≥ 100
- Calculates complete cycles: `completeCycles = floor(value/100)`

### 3. Reward Calculation
- **Old system:** Always 1 car regardless of counter value
- **New system:** `completeCycles` cars (e.g., 300/100 = 3 cars)
- Preserves overflow for next cycle: `remainder = value % 100`

### 4. Memory Management
- Resets counters to remainder value
- Intercepts reward methods to return correct amounts
- Handles spin value additions (30/29 values)

## 🎯 Available Commands

When using the Python controller:

### Basic Commands
- `reset` - Manually reset crate counter
- `status` - Check current counter values
- `scan` - Scan for counter memory locations
- `help` - Show available commands
- `exit` - Exit the program

### Advanced Commands
- `pattern` - Search for GameGuardian pattern
- `monitor` - Toggle pattern monitoring
- `values` - Show monitored memory values
- `debug` - Enable debug logging

## 📊 Expected Results

| Scenario | Old Result | New Result (Fixed) |
|----------|------------|-------------------|
| 300 crates | 1 car | **3 cars** |
| 450 crates | 1 car | **4 cars** (50 remaining) |
| 150 crates | 1 car | **1 car** (50 remaining) |
| 99 crates | 0 cars | **0 cars** (wait for next) |
| 200 crates | 1 car | **2 cars** (0 remaining) |

## 💡 Usage Examples

### Basic Operation
```bash
$ python crate_counter_controller.py
[*] Connected to USB device
[*] Found GameGuardian pattern at: 0x12345678
[*] Monitoring crate counters...

DriveZone> status
[*] Current counter values: 250/100
[*] Expected reward: 2 cars (50 remaining)

DriveZone> reset
[*] Counter manually reset to 50
[*] Reward calculation: 2 cars delivered
```

### Pattern Detection
```bash
DriveZone> pattern
[*] Searching for GameGuardian pattern...
[*] Found pattern at: 0x12345678
[*] Pattern values: [1514, 250, 1514, 150]
[*] Monitoring enabled
```

### Real-time Monitoring
```bash
[*] Counter reached limit - val2: 300, val4: 150
[*] Complete cycles: 3, remainder: 0
[*] Calculated reward: 3 cars
[*] Counter reset from 300 to 0
[*] FIXED: 300/100 = 3 cars, not 1 car!
```

## 🔍 Technical Details

### Android Compatibility
- **IL2CPP Module:** `libil2cpp.so` (primary target)
- **Unity Modules:** `libunity.so`, `libgame.so`
- **Fallback:** `GameAssembly.dll` for emulators

### Memory Scanning
- **Pattern Search:** Little-endian hex pattern matching
- **Range Types:** Read-write memory regions only
- **Validation:** Multi-value pattern verification

### Hook Implementation
- **Export Enumeration:** Scans module exports for relevant functions
- **Function Interception:** Frida Interceptor for method hooking
- **Memory Patching:** Direct memory address modification

## 🛠️ Troubleshooting

### Common Issues

**"No device found"**
- Check USB debugging is enabled
- Verify device is connected via USB
- Try `adb devices` to confirm connection

**"Pattern not found"**
- Make sure you're in the game's crate screen
- Try manually opening and closing crates
- Use `pattern` command to rescan

**"Permission denied"**
- Some devices require root access
- Try enabling "Apps from unknown sources"
- Check if SELinux is blocking access

**"Counter not resetting"**
- Verify GameGuardian pattern is active
- Try manual reset with `reset` command
- Check if game version is supported

### Debug Mode
Enable detailed logging:
```bash
python crate_counter_controller.py --debug
```

## 🔒 Safety and Legal Notes

### Safety Precautions
- **Backup your save data** before using
- **Test in offline mode** first
- **Use at your own risk** - may affect game stability
- **Monitor for game updates** - hooks may need adjustment

### Detection Risks
- **Online play** - modifications may be detected
- **Anti-cheat systems** - use with caution
- **Account bans** - possible if detected

### Legal Disclaimer
This tool is for educational and research purposes only. Use responsibly and in accordance with:
- Game's terms of service
- Local laws and regulations
- Platform policies

## 📱 Device Compatibility

### Tested Android Versions
- **Android 8.0+** (API 26+)
- **ARM64** architecture preferred
- **ARMv7** architecture supported

### Tested Devices
- Samsung Galaxy series
- Google Pixel series
- OnePlus devices
- Xiaomi devices

### Emulator Support
- **BlueStacks** (limited support)
- **NoxPlayer** (limited support)
- **LDPlayer** (limited support)

## 🚀 Performance Optimization

### Device Performance
- **Close background apps** to free RAM
- **Disable battery optimization** for better performance
- **Use stable USB connection** to prevent disconnections

### Script Performance
- **Monitor CPU usage** during operation
- **Use interval-based scanning** instead of continuous
- **Limit debug logging** in production use

## 🎨 Customization

### Modifying Reward Calculation
Edit the `handleCounterReward` function in `crate_counter_reset.js`:

```javascript
function handleCounterReward(counterAddress, currentValue) {
    // Custom cycle calculation
    var completeCycles = Math.floor(currentValue / 100);
    var remainder = currentValue % 100;
    
    // Custom reward multiplier
    lastRewardCalculation = completeCycles * 1; // 1 car per cycle
    
    // Custom counter reset
    Memory.writeInt32(counterAddress, remainder);
}
```

## 🆘 Support and Help

### Getting Help
1. Check the troubleshooting section
2. Review example sessions
3. Verify device compatibility
4. Test with debug mode enabled

### Common Solutions
- **Restart the game** and try again
- **Reconnect USB** if connection drops
- **Clear app cache** if behavior is inconsistent
- **Update Frida** to latest version

## 🎮 Example Session

```
$ python crate_counter_controller.py
[*] Drive Zone Online - Android Crate Counter Fix
[*] Connecting to USB device...
[*] Found device: SM-G975F
[*] Searching for Drive Zone Online process...
[*] Found process: Drive Zone Online (PID: 12345)
[*] Injecting crate counter fix...
[*] Searching for GameGuardian pattern...
[*] Found pattern at: 0x7f8e4c2000
[*] Pattern values: [1514, 180, 1514, 220]
[*] Monitoring enabled - waiting for counter limit...

[*] Counter reached limit - val2: 300, val4: 150
[*] Complete cycles: 3, remainder: 0
[*] Calculated reward: 3 cars
[*] Counter reset from 300 to 0
[*] SUCCESS: 300/100 = 3 cars delivered!

DriveZone> status
[*] Current counters: 0/100, 50/100
[*] Total cars earned: 3
[*] System working correctly!

DriveZone> exit
[*] Disconnecting from device...
[*] Crate counter fix disabled
[*] Goodbye!
```

---

**Happy gaming! 🎮🎁**
