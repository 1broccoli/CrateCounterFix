// Frida script to modify the crate counter system in Drive Zone Online
// This script hooks into the progression system to give proper rewards
// Based on GameGuardian search pattern: 1,514Q;200~80000Q;1,514Q;200~80000::25
// FIXED: 300/100 = 3 cars, not 1 car (proper reward calculation)

console.log("[*] Drive Zone Online - Crate Counter Reset Script (Android - GameGuardian Pattern)");

// Global variables based on GameGuardian search pattern
var currentCrateCount = 0;
var maxCrateCount = 100; // Changed from 160 to 100 for proper reward calculation
var spinValue = 30; // Value added after first set (29 with lag)
var crateCounterAddresses = [];
var progressionWidgetAddresses = [];
var ggSearchPattern = [1514, 200, 80000, 1514, 200, 80000]; // GameGuardian pattern
var monitoredValues = new Map();
var rewardCalculationEnabled = true; // Enable proper reward calculation
var lastRewardCalculation = 0;
var pendingRewards = 0; // Track how many cars we should give

// Hook into the progression system
function hookProgressionSystem() {
    console.log("[*] Setting up progression system hooks for Android...");
    
    // For Android, try different module names
    var moduleNames = ["GameAssembly.dll", "libil2cpp.so", "libunity.so", "libgame.so"];
    var moduleBase = null;
    
    for (var i = 0; i < moduleNames.length; i++) {
        try {
            moduleBase = Module.findBaseAddress(moduleNames[i]);
            if (moduleBase) {
                console.log("[*] Found module: " + moduleNames[i] + " at " + moduleBase);
                break;
            }
        } catch (e) {
            // Module not found, try next
        }
    }
    
    if (moduleBase) {
        console.log("[*] Module base address: " + moduleBase);
        
        // Search for crate counter update patterns
        findCrateCounterMethods();
        
        // Hook box progression widget updates
        hookBoxProgressionUpdates();
    } else {
        console.log("[!] No suitable module found for Android");
    }
}

function findCrateCounterMethods() {
    console.log("[*] Searching for crate counter methods using GameGuardian pattern...");
    
    // Search for the GameGuardian pattern: 1,514Q;200~80000Q;1,514Q;200~80000::25
    searchGameGuardianPattern();
    
    // Hook into UI text updates that might show "x/100"
    hookUITextUpdates();
    
    // Hook into reward calculation methods
    hookRewardCalculation();
    
    // Hook spin value addition (30 or 29 with lag)
    hookSpinValueAddition();
}

function searchGameGuardianPattern() {
    console.log("[*] Searching for GameGuardian pattern: 1,514Q;200~80000Q;1,514Q;200~80000::25");
    
    var ranges = Process.enumerateRanges('rw-');
    var foundPatterns = [];
    
    ranges.forEach(function(range) {
        try {
            // Search for the specific value 1514 (0x5EA in hex)
            var pattern1514 = "EA 05 00 00"; // 1514 in little-endian hex
            var results = Memory.scanSync(range.base, range.size, pattern1514);
            
            results.forEach(function(result) {
                // Check if this is part of the GameGuardian pattern
                if (validateGameGuardianPattern(result.address)) {
                    console.log("[*] Found GameGuardian pattern at: " + result.address);
                    foundPatterns.push(result.address);
                    monitorGameGuardianPattern(result.address);
                }
            });
        } catch (e) {
            // Range not accessible, skip
        }
    });
    
    console.log("[*] Found " + foundPatterns.length + " GameGuardian patterns");
}

function validateGameGuardianPattern(address) {
    try {
        // Check if this address contains the expected pattern
        var val1 = Memory.readInt32(address);           // Should be 1514
        var val2 = Memory.readInt32(address.add(4));    // Should be 200-80000 range
        var val3 = Memory.readInt32(address.add(8));    // Should be 1514
        var val4 = Memory.readInt32(address.add(12));   // Should be 200-80000 range
        
        return val1 === 1514 && 
               val2 >= 200 && val2 <= 80000 &&
               val3 === 1514 && 
               val4 >= 200 && val4 <= 80000;
    } catch (e) {
        return false;
    }
}

function monitorGameGuardianPattern(baseAddress) {
    console.log("[*] Monitoring GameGuardian pattern at: " + baseAddress);
    
    // Monitor the values in the pattern
    setInterval(function() {
        try {
            var val1 = Memory.readInt32(baseAddress);
            var val2 = Memory.readInt32(baseAddress.add(4));
            var val3 = Memory.readInt32(baseAddress.add(8));
            var val4 = Memory.readInt32(baseAddress.add(12));
            
            // Check if val2 or val4 (the counter values) need reward calculation
            if (val2 >= 100 || val4 >= 100) {
                console.log("[*] Counter reached limit - val2: " + val2 + ", val4: " + val4);
                
                // Calculate proper rewards and reset counters
                if (val2 >= 100) {
                    handleCounterReward(baseAddress.add(4), val2);
                }
                if (val4 >= 100) {
                    handleCounterReward(baseAddress.add(12), val4);
                }
            }
        } catch (e) {
            console.log("[!] Error monitoring pattern: " + e);
        }
    }, 1000); // Check every second
}

function handleCounterReward(counterAddress, currentValue) {
    console.log("[*] Handling counter reward - current value: " + currentValue);
    
    // Calculate how many complete 100-cycles we have (FIXED: was 160)
    var completeCycles = Math.floor(currentValue / 100);
    var remainder = currentValue % 100;
    
    console.log("[*] Complete cycles: " + completeCycles + ", remainder: " + remainder);
    
    // Store the reward calculation for the reward hook
    lastRewardCalculation = completeCycles; // 1 car per complete cycle (FIXED: was completeCycles * 4)
    
    console.log("[*] Calculated reward: " + lastRewardCalculation + " cars");
    
    // Reset counter to the remainder
    try {
        Memory.writeInt32(counterAddress, remainder);
        console.log("[*] Counter reset from " + currentValue + " to " + remainder);
    } catch (e) {
        console.log("[!] Failed to reset counter: " + e);
    }
}

function hookSpinValueAddition() {
    console.log("[*] Hooking spin value addition (30/29 with lag) for Android...");
    
    // Hook into methods that might add the spin value
    var moduleNames = ["libil2cpp.so", "GameAssembly.dll"];
    
    moduleNames.forEach(function(moduleName) {
        try {
            var exports = Module.enumerateExports(moduleName);
            
            exports.forEach(function(exp) {
                if (exp.name.includes("Add") || 
                    exp.name.includes("Increment") || 
                    exp.name.includes("Spin") ||
                    exp.name.includes("Update")) {
                    
                    try {
                        Interceptor.attach(exp.address, {
                            onEnter: function(args) {
                                // Check for spin value addition (30 or 29)
                                for (var i = 0; i < args.length; i++) {
                                    try {
                                        var value = args[i].toInt32();
                                        if (value === 30 || value === 29) {
                                            console.log("[*] Spin value detected: " + value);
                                            
                                            // Check if adding this would exceed the limit
                                            var currentCounter = getCurrentCounterValue();
                                            if (currentCounter + value >= 100) {
                                                console.log("[*] Spin value would exceed limit, calculating proper reward...");
                                                
                                                // Calculate total value after spin
                                                var totalValue = currentCounter + value;
                                                var completeCycles = Math.floor(totalValue / 100);
                                                var remainder = totalValue % 100;
                                                
                                                console.log("[*] Total value: " + totalValue + ", cycles: " + completeCycles + ", remainder: " + remainder);
                                                
                                                // Store reward calculation (1 car per cycle)
                                                lastRewardCalculation = completeCycles;
                                                
                                                // Set spin value to create the remainder
                                                var adjustedSpin = remainder - currentCounter;
                                                if (adjustedSpin >= 0) {
                                                    args[i] = ptr(adjustedSpin);
                                                    console.log("[*] Adjusted spin value to: " + adjustedSpin);
                                                }
                                            }
                                        }
                                    } catch (e) {
                                        // Not an integer, skip
                                    }
                                }
                            }
                        });
                    } catch (e) {
                        // Failed to hook, continue
                    }
                }
            });
        } catch (e) {
            // Module not found, try next
        }
    });
}

function getCurrentCounterValue() {
    // Get current counter value from monitored addresses
    var maxValue = 0;
    
    monitoredValues.forEach(function(value, address) {
        try {
            var currentValue = Memory.readInt32(address);
            if (currentValue > maxValue) {
                maxValue = currentValue;
            }
        } catch (e) {
            // Address no longer valid
        }
    });
    
    return maxValue;
}

function resetAllCounters() {
    console.log("[*] Resetting all counters to maintain proper rewards...");
    
    // Reset GameGuardian pattern counters
    monitoredValues.forEach(function(value, address) {
        try {
            Memory.writeInt32(address, 0);
            console.log("[*] Reset counter at: " + address);
        } catch (e) {
            console.log("[!] Failed to reset counter at: " + address);
        }
    });
    
    // Reset internal counter addresses
    crateCounterAddresses.forEach(function(addr) {
        try {
            Memory.writeInt32(addr, 0);
            console.log("[*] Reset internal counter at: " + addr);
        } catch (e) {
            console.log("[!] Failed to reset internal counter at: " + addr);
        }
    });
}

function hookUITextUpdates() {
    console.log("[*] Hooking UI text updates for Android...");
    
    // Hook TextMeshProUGUI.set_text to intercept counter displays
    var moduleNames = ["libil2cpp.so", "GameAssembly.dll"];
    
    moduleNames.forEach(function(moduleName) {
        try {
            var textMeshSetText = Module.findExportByName(moduleName, "TextMeshProUGUI_set_text");
            if (textMeshSetText) {
                console.log("[*] Found TextMeshProUGUI.set_text at: " + textMeshSetText + " in " + moduleName);
                
                Interceptor.attach(textMeshSetText, {
                    onEnter: function(args) {
                        // args[0] = TextMeshProUGUI instance
                        // args[1] = string text
                        
                        try {
                            var textPtr = args[1];
                            if (textPtr && !textPtr.isNull()) {
                                var text = Memory.readUtf16String(textPtr);
                                
                                // Check if this is a crate counter text (x/100 format)
                                if (text && text.includes("/100")) {
                                    console.log("[*] Crate counter text detected: " + text);
                                    
                                    // Parse the current count
                                    var match = text.match(/(\d+)\/100/);
                                    if (match) {
                                        var currentCount = parseInt(match[1]);
                                        console.log("[*] Current crate count: " + currentCount);
                                        
                                        // Store this for monitoring
                                        currentCrateCount = currentCount;
                                        
                                        // If count >= 100, reset it to maintain proper rewards
                                        if (currentCount >= 100) {
                                            console.log("[*] Resetting crate counter display to maintain proper rewards");
                                            
                                            // Calculate remaining value after reset
                                            var overflow = currentCount - 100;
                                            var newDisplayValue = Math.min(overflow, 99);
                                            
                                            var newText = text.replace(/(\d+)\/100/, newDisplayValue + "/100");
                                            
                                            // Update the text to show reset counter
                                            var newTextPtr = Memory.allocUtf16String(newText);
                                            args[1] = newTextPtr;
                                            
                                            // Also trigger internal counter reset
                                            resetInternalCrateCounter();
                                        }
                                    }
                                }
                            }
                        } catch (e) {
                            console.log("[!] Error in text hook: " + e);
                        }
                    }
                });
            }
        } catch (e) {
            // Module not found, try next
        }
    });
}

function hookRewardCalculation() {
    console.log("[*] Hooking reward calculation methods for Android...");
    
    // Hook into reward calculation methods to ensure proper rewards
    // This is where the game decides how many cars to give
    
    // Look for methods that might be named something like "CalculateReward" or similar
    var rewardMethods = [
        "CalculateReward",
        "GetRewardAmount",
        "ProcessReward",
        "ClaimReward"
    ];
    
    var moduleNames = ["libil2cpp.so", "GameAssembly.dll"];
    
    moduleNames.forEach(function(moduleName) {
        try {
            rewardMethods.forEach(function(methodName) {
                var methodPtr = Module.findExportByName(moduleName, methodName);
                if (methodPtr) {
                    console.log("[*] Found reward method: " + methodName + " in " + moduleName);
                    
                    Interceptor.attach(methodPtr, {
                        onEnter: function(args) {
                            console.log("[*] Reward calculation method called: " + methodName);
                        },
                        onLeave: function(retval) {
                            // If we have pending rewards, return that amount
                            if (lastRewardCalculation > 0) {
                                console.log("[*] Returning calculated reward: " + lastRewardCalculation + " cars");
                                retval.replace(ptr(lastRewardCalculation));
                                lastRewardCalculation = 0; // Reset after use
                            }
                        }
                    });
                }
            });
        } catch (e) {
            // Module not found, try next
        }
    });
}

function hookBoxProgressionUpdates() {
    console.log("[*] Hooking box progression updates for Android...");
    
    // Hook into the Core_UI_ProgressionWithRewardsWidget methods
    // These handle the progression system
    
    var moduleNames = ["libil2cpp.so", "GameAssembly.dll"];
    
    moduleNames.forEach(function(moduleName) {
        try {
            // Search for methods that update the progression counter
            var progressionMethods = Module.enumerateExports(moduleName).filter(function(exp) {
                return exp.name.includes("ProgressionWithRewards") || 
                       exp.name.includes("BoxProgression") ||
                       exp.name.includes("UpdateCounter") ||
                       exp.name.includes("1514"); // Look for methods containing the GameGuardian pattern
            });
            
            progressionMethods.forEach(function(method) {
                console.log("[*] Found progression method: " + method.name + " in " + moduleName);
                
                Interceptor.attach(method.address, {
                    onEnter: function(args) {
                        console.log("[*] Progression method called: " + method.name);
                        
                        // Check if this is updating a counter
                        if (method.name.includes("Update") || method.name.includes("Counter")) {
                            // Look for counter values in the arguments
                            for (var i = 0; i < args.length; i++) {
                                try {
                                    var value = args[i].toInt32();
                                    
                                    // Check for GameGuardian pattern values
                                    if (value === 1514) {
                                        console.log("[*] GameGuardian pattern value detected: " + value);
                                    }
                                    
                                    // Check for counter values approaching limit
                                    if (value >= 100) {
                                        console.log("[*] Counter value >= 100 detected: " + value);
                                        
                                        // Calculate overflow and reset
                                        var overflow = value - 100;
                                        var newValue = Math.min(overflow, 99);
                                        
                                        console.log("[*] Resetting counter from " + value + " to " + newValue);
                                        args[i] = ptr(newValue);
                                    }
                                    
                                    // Check for spin values (30 or 29)
                                    if (value === 30 || value === 29) {
                                        console.log("[*] Spin value detected: " + value);
                                        
                                        // Check if this would cause overflow
                                        var currentCounter = getCurrentCounterValue();
                                        if (currentCounter + value >= 100) {
                                            var safeValue = Math.max(0, 99 - currentCounter);
                                            console.log("[*] Adjusting spin value from " + value + " to " + safeValue);
                                            args[i] = ptr(safeValue);
                                        }
                                    }
                                } catch (e) {
                                    // Not an integer, skip
                                }
                            }
                        }
                    }
                });
            });
        } catch (e) {
            // Module not found, try next
        }
    });
}

function resetInternalCrateCounter() {
    console.log("[*] Resetting internal crate counter...");
    
    // Reset GameGuardian pattern counters
    resetAllCounters();
    
    // Search for crate counter memory addresses and reset them
    if (crateCounterAddresses.length > 0) {
        crateCounterAddresses.forEach(function(addr) {
            try {
                Memory.writeInt32(addr, 0);
                console.log("[*] Reset counter at address: " + addr);
            } catch (e) {
                console.log("[!] Failed to reset counter at: " + addr);
            }
        });
    }
    
    // Also scan for new GameGuardian pattern locations
    setTimeout(function() {
        searchGameGuardianPattern();
    }, 1000);
}

// Memory scanning functions
function scanForCrateCounters() {
    console.log("[*] Scanning for crate counter memory locations...");
    
    // First, search for GameGuardian pattern
    searchGameGuardianPattern();
    
    // Then scan for values around 100 (the max counter value)
    var ranges = Process.enumerateRanges('rw-');
    ranges.forEach(function(range) {
        try {
            var results = Memory.scanSync(range.base, range.size, "64 00 00 00"); // 100 in hex
            results.forEach(function(result) {
                var value = Memory.readInt32(result.address);
                if (value === 100) {
                    console.log("[*] Found potential crate counter at: " + result.address);
                    crateCounterAddresses.push(result.address);
                    monitoredValues.set(result.address, value);
                }
            });
        } catch (e) {
            // Range not accessible, skip
        }
    });
    
    // Also scan for spin values (30 and 29)
    scanForSpinValues();
}

function scanForSpinValues() {
    console.log("[*] Scanning for spin value locations (30/29)...");
    
    var ranges = Process.enumerateRanges('rw-');
    ranges.forEach(function(range) {
        try {
            // Scan for 30 (0x1E)
            var results30 = Memory.scanSync(range.base, range.size, "1E 00 00 00");
            results30.forEach(function(result) {
                var value = Memory.readInt32(result.address);
                if (value === 30) {
                    console.log("[*] Found spin value 30 at: " + result.address);
                    monitoredValues.set(result.address, value);
                }
            });
            
            // Scan for 29 (0x1D)
            var results29 = Memory.scanSync(range.base, range.size, "1D 00 00 00");
            results29.forEach(function(result) {
                var value = Memory.readInt32(result.address);
                if (value === 29) {
                    console.log("[*] Found spin value 29 at: " + result.address);
                    monitoredValues.set(result.address, value);
                }
            });
        } catch (e) {
            // Range not accessible, skip
        }
    });
}

// RPC exports for external control
rpc.exports = {
    resetCrateCounter: function() {
        console.log("[*] Manual crate counter reset requested");
        resetInternalCrateCounter();
        return "Counter reset";
    },
    
    getCrateCount: function() {
        return currentCrateCount;
    },
    
    setMaxCrateCount: function(newMax) {
        maxCrateCount = newMax;
        console.log("[*] Max crate count set to: " + newMax);
        return "Max count updated";
    },
    
    setSpinValue: function(newSpin) {
        spinValue = newSpin;
        console.log("[*] Spin value set to: " + newSpin);
        return "Spin value updated";
    },
    
    scanCounters: function() {
        scanForCrateCounters();
        return "Scan completed";
    },
    
    searchGameGuardianPattern: function() {
        searchGameGuardianPattern();
        return "GameGuardian pattern search completed";
    },
    
    getMonitoredValues: function() {
        var values = {};
        monitoredValues.forEach(function(value, address) {
            try {
                values[address.toString()] = Memory.readInt32(address);
            } catch (e) {
                values[address.toString()] = "Invalid";
            }
        });
        return values;
    }
};

// Initialize the hooks
function main() {
    console.log("[*] Initializing crate counter reset system...");
    
    // Wait for the game to load
    setTimeout(function() {
        hookProgressionSystem();
        scanForCrateCounters();
    }, 3000);
}

// Start the script
main();

console.log("[*] Crate counter reset script loaded successfully!");
console.log("[*] GameGuardian pattern: 1,514Q;200~80000Q;1,514Q;200~80000::25");
console.log("[*] The script will automatically reset your crate counter when it reaches 100");
console.log("[*] Spin values (30/29) will be monitored and adjusted to prevent overflow");
console.log("[*] FIXED: 300/100 = 3 cars, not 1 car (proper reward calculation)");
console.log("[*] Any values gained over 100 will be preserved in the next cycle");
