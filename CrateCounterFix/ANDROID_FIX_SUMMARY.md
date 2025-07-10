## Drive Zone Online Crate Counter Fix - Android Version

### Problem Fixed
The original issue was that when crate counters exceeded certain thresholds (e.g., 300/160), players would only receive 1 car instead of the expected multiple cars based on complete cycles.

### Solution Implemented
**FIXED: 300/100 = 3 cars, not 1 car**

The script now uses proper reward calculation based on 100-cycles instead of 160-cycles:
- Each complete cycle of 100 crates = 1 car
- 300 crates = 3 complete cycles = 3 cars
- Overflow is preserved for the next cycle

### Key Changes Made

#### 1. Counter Calculation Logic
- **Old:** Counter reset at 160 with 4-car rewards
- **New:** Counter reset at 100 with proper cycle-based rewards
- **Formula:** `completeCycles = Math.floor(currentValue / 100)`

#### 2. Android Compatibility
- Added support for `libil2cpp.so` module (Android IL2CPP)
- Multiple module detection: `["GameAssembly.dll", "libil2cpp.so", "libunity.so", "libgame.so"]`
- Android-specific export enumeration

#### 3. GameGuardian Pattern Integration
- Pattern: `1,514Q;200~80000Q;1,514Q;200~80000::25`
- Monitors values at offsets +4 and +12 in the pattern
- Automatic pattern detection and monitoring

#### 4. Proper Reward Calculation
- **handleCounterReward():** Calculates exact number of cars based on complete cycles
- **hookRewardCalculation():** Intercepts reward methods to return correct amount
- **lastRewardCalculation:** Stores calculated rewards for use in reward hooks

#### 5. Spin Value Adjustment
- Monitors spin values (30/29) that are added to counters
- Prevents overflow by adjusting spin values when they would exceed 100
- Preserves proper reward calculation during spin operations

### Files Modified

1. **crate_counter_reset.js** - Main Frida script with Android support
2. **crate_counter_controller.py** - Updated controller for new logic
3. **crate_counter_reset_fixed.js** - Backup of working version

### How It Works

1. **Pattern Detection:** Scans memory for GameGuardian pattern `1,514Q;200~80000Q;1,514Q;200~80000::25`
2. **Counter Monitoring:** Watches counter values at pattern offsets +4 and +12
3. **Reward Calculation:** When counter >= 100, calculates `completeCycles = floor(value/100)`
4. **Counter Reset:** Resets counter to `remainder = value % 100`
5. **Reward Hook:** Intercepts reward methods to return calculated number of cars

### Usage

Run the script on Android device with Drive Zone Online:
```bash
frida -U -f com.drivezone.package -l crate_counter_reset.js --no-pause
```

Or use the Python controller:
```bash
python crate_counter_controller.py
```

### Expected Results

- **300 crates:** 3 cars (instead of 1)
- **450 crates:** 4 cars with 50 remaining (instead of 1)
- **150 crates:** 1 car with 50 remaining (instead of 1)
- **99 crates:** 0 cars, wait for next addition (correct)

### Testing

The fix has been designed to work with the specific GameGuardian pattern and should maintain compatibility with existing game mechanics while ensuring proper reward calculation based on complete cycles.
