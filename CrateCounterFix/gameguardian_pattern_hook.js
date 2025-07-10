// GameGuardian Pattern-Specific Crate Counter Script
// Targets the exact pattern: 1,514Q;200~80000Q;1,514Q;200~80000::25

console.log("[*] GameGuardian Pattern Crate Counter Script");
console.log("[*] Pattern: 1,514Q;200~80000Q;1,514Q;200~80000::25");

// Configuration based on your GameGuardian search
var GG_PATTERN = {
    value1: 1514,
    range_min: 200,
    range_max: 80000,
    value2: 1514,
    search_type: "QWORD", // Q in GameGuardian
    group_size: 25
};

var SPIN_VALUE_NORMAL = 30;
var SPIN_VALUE_LAG = 29;
var MAX_COUNTER = 160;

// Storage for found patterns
var foundPatterns = [];
var activeCounters = new Map();

function initializeGameGuardianHook() {
    console.log("[*] Initializing GameGuardian pattern hook...");
    
    setTimeout(function() {
        searchForGameGuardianPattern();
        setupPatternMonitoring();
        hookCounterOperations();
    }, 2000);
}

function searchForGameGuardianPattern() {
    console.log("[*] Searching for GameGuardian pattern...");
    console.log("[*] Looking for: 1514, 200-80000, 1514, 200-80000");
    
    var ranges = Process.enumerateRanges('rw-');
    var patternsFound = 0;
    
    ranges.forEach(function(range) {
        if (range.size > 0x1000) { // Skip small ranges
            try {
                scanRangeForPattern(range);
            } catch (e) {
                // Range not accessible
            }
        }
    });
    
    console.log("[*] Found " + foundPatterns.length + " GameGuardian patterns");
}

function scanRangeForPattern(range) {
    // Search for 1514 (0x5EA in hex)
    var pattern = "EA 05 00 00"; // 1514 in little-endian
    
    try {
        var results = Memory.scanSync(range.base, range.size, pattern);
        
        results.forEach(function(result) {
            if (validateFullPattern(result.address)) {
                console.log("[*] Valid GameGuardian pattern found at: " + result.address);
                foundPatterns.push(result.address);
                setupPatternMonitor(result.address);
            }
        });
    } catch (e) {
        // Scan failed, continue
    }
}

function validateFullPattern(address) {
    try {
        // Read the full pattern: [1514][200-80000][1514][200-80000]
        var val1 = Memory.readInt32(address);
        var val2 = Memory.readInt32(address.add(4));
        var val3 = Memory.readInt32(address.add(8));
        var val4 = Memory.readInt32(address.add(12));
        
        // Validate pattern
        var isValid = (val1 === GG_PATTERN.value1) &&
                      (val2 >= GG_PATTERN.range_min && val2 <= GG_PATTERN.range_max) &&
                      (val3 === GG_PATTERN.value2) &&
                      (val4 >= GG_PATTERN.range_min && val4 <= GG_PATTERN.range_max);
        
        if (isValid) {
            console.log("[*] Pattern validation: " + val1 + ", " + val2 + ", " + val3 + ", " + val4);
            
            // Store counter addresses for monitoring
            activeCounters.set(address.add(4), val2);  // First counter
            activeCounters.set(address.add(12), val4); // Second counter
        }
        
        return isValid;
    } catch (e) {
        return false;
    }
}

function setupPatternMonitor(patternAddress) {
    console.log("[*] Setting up monitor for pattern at: " + patternAddress);
    
    // Monitor both counter values in the pattern
    var counter1Addr = patternAddress.add(4);  // Second value (counter 1)
    var counter2Addr = patternAddress.add(12); // Fourth value (counter 2)
    
    // Set up periodic monitoring
    setInterval(function() {
        try {
            var counter1 = Memory.readInt32(counter1Addr);
            var counter2 = Memory.readInt32(counter2Addr);
            
            // Check if either counter needs reset
            if (counter1 >= MAX_COUNTER) {
                console.log("[*] Counter 1 reached " + counter1 + " - resetting");
                handleCounterReset(counter1Addr, counter1);
            }
            
            if (counter2 >= MAX_COUNTER) {
                console.log("[*] Counter 2 reached " + counter2 + " - resetting");
                handleCounterReset(counter2Addr, counter2);
            }
        } catch (e) {
            console.log("[!] Error monitoring pattern: " + e);
        }
    }, 500); // Check every 500ms
}

function handleCounterReset(counterAddress, currentValue) {
    console.log("[*] Handling counter reset - current value: " + currentValue);
    
    // Calculate overflow (value beyond 160)
    var overflow = currentValue - MAX_COUNTER;
    
    // Reset to preserve overflow for next cycle
    var newValue = Math.max(0, Math.min(overflow, MAX_COUNTER - 1));
    
    console.log("[*] Resetting counter from " + currentValue + " to " + newValue);
    console.log("[*] Overflow preserved: " + overflow);
    
    try {
        Memory.writeInt32(counterAddress, newValue);
        console.log("[*] Counter reset successful");
    } catch (e) {
        console.log("[!] Failed to reset counter: " + e);
    }
}

function setupPatternMonitoring() {
    console.log("[*] Setting up pattern monitoring...");
    
    // Monitor for new patterns appearing
    setInterval(function() {
        searchForGameGuardianPattern();
    }, 10000); // Search every 10 seconds
}

function hookCounterOperations() {
    console.log("[*] Hooking counter operations...");
    
    // Hook operations that might modify the counters
    var exports = Module.enumerateExports("GameAssembly.dll");
    
    exports.forEach(function(exp) {
        if (exp.name.includes("Add") || 
            exp.name.includes("Increment") || 
            exp.name.includes("Update") ||
            exp.name.includes("Set")) {
            
            try {
                Interceptor.attach(exp.address, {
                    onEnter: function(args) {
                        // Check for spin values
                        for (var i = 0; i < args.length; i++) {
                            try {
                                var value = args[i].toInt32();
                                
                                // Detect spin values
                                if (value === SPIN_VALUE_NORMAL || value === SPIN_VALUE_LAG) {
                                    console.log("[*] Spin value detected: " + value);
                                    
                                    // Check if this would cause overflow
                                    var wouldOverflow = checkForPotentialOverflow(value);
                                    if (wouldOverflow) {
                                        console.log("[*] Spin value would cause overflow, adjusting...");
                                        var safeValue = calculateSafeSpinValue(value);
                                        args[i] = ptr(safeValue);
                                        console.log("[*] Adjusted spin value to: " + safeValue);
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
}

function checkForPotentialOverflow(spinValue) {
    // Check if adding spin value would cause any counter to exceed 160
    var wouldOverflow = false;
    
    activeCounters.forEach(function(value, address) {
        try {
            var currentValue = Memory.readInt32(address);
            if (currentValue + spinValue >= MAX_COUNTER) {
                wouldOverflow = true;
            }
        } catch (e) {
            // Address no longer valid
        }
    });
    
    return wouldOverflow;
}

function calculateSafeSpinValue(originalSpin) {
    // Calculate a safe spin value that won't cause overflow
    var maxSafeValue = 0;
    
    activeCounters.forEach(function(value, address) {
        try {
            var currentValue = Memory.readInt32(address);
            var safeForThis = Math.max(0, MAX_COUNTER - 1 - currentValue);
            maxSafeValue = Math.max(maxSafeValue, safeForThis);
        } catch (e) {
            // Address no longer valid
        }
    });
    
    return Math.min(originalSpin, maxSafeValue);
}

// RPC exports for external control
rpc.exports = {
    scanPattern: function() {
        searchForGameGuardianPattern();
        return "Pattern scan completed. Found: " + foundPatterns.length;
    },
    
    getPatterns: function() {
        return foundPatterns.map(function(addr) {
            return {
                address: addr.toString(),
                values: getPatternValues(addr)
            };
        });
    },
    
    getCounters: function() {
        var counters = {};
        activeCounters.forEach(function(value, address) {
            try {
                counters[address.toString()] = Memory.readInt32(address);
            } catch (e) {
                counters[address.toString()] = "Invalid";
            }
        });
        return counters;
    },
    
    resetAllCounters: function() {
        var resetCount = 0;
        activeCounters.forEach(function(value, address) {
            try {
                Memory.writeInt32(address, 0);
                resetCount++;
            } catch (e) {
                // Failed to reset
            }
        });
        return "Reset " + resetCount + " counters";
    },
    
    setSpinValues: function(normal, lag) {
        SPIN_VALUE_NORMAL = normal;
        SPIN_VALUE_LAG = lag;
        return "Spin values updated: " + normal + "/" + lag;
    }
};

function getPatternValues(address) {
    try {
        return [
            Memory.readInt32(address),
            Memory.readInt32(address.add(4)),
            Memory.readInt32(address.add(8)),
            Memory.readInt32(address.add(12))
        ];
    } catch (e) {
        return [0, 0, 0, 0];
    }
}

// Initialize the script
initializeGameGuardianHook();

console.log("[*] GameGuardian Pattern Hook loaded successfully");
console.log("[*] Monitoring for pattern: 1514, 200-80000, 1514, 200-80000");
console.log("[*] Spin values: " + SPIN_VALUE_NORMAL + " (normal), " + SPIN_VALUE_LAG + " (lag)");
console.log("[*] Will reset counters at " + MAX_COUNTER + " while preserving overflow");
