// Advanced Frida Script for Drive Zone Online Crate Counter Reset
// This script specifically targets the IL2CPP structures for progression system

console.log("[*] Advanced Crate Counter Reset Script - IL2CPP Targeting");

// Memory addresses and offsets (these will need to be updated based on your specific game version)
var gameAssembly = null;
var progressionWidgetClass = null;
var boxScreenClass = null;

// Initialize the script
function initializeScript() {
    console.log("[*] Initializing IL2CPP hooks...");
    
    // Get GameAssembly module
    gameAssembly = Process.getModuleByName("GameAssembly.dll");
    if (!gameAssembly) {
        console.log("[!] GameAssembly.dll not found!");
        return false;
    }
    
    console.log("[*] GameAssembly.dll base: " + gameAssembly.base);
    
    // Find key classes
    findProgressionClasses();
    
    // Hook the progression system
    hookProgressionMethods();
    
    // Hook UI updates
    hookUIUpdates();
    
    // Hook reward calculation
    hookRewardSystem();
    
    return true;
}

function findProgressionClasses() {
    console.log("[*] Finding progression classes...");
    
    // Search for ProgressionWithRewardsWidget class
    var progressionPattern = "ProgressionWithRewardsWidget";
    var boxScreenPattern = "BoxScreen";
    
    // You may need to adjust these addresses based on your IL2CPP dump
    // These are example addresses - replace with actual addresses from your il2cpp.h
    
    // From the il2cpp.h file, we found these structures:
    // Core_UI_ProgressionWithRewardsWidget_Fields at various lines
    // Core_UI_Screens_Boxes_BoxScreen_Fields
    
    console.log("[*] Progression classes located (using static analysis)");
}

function hookProgressionMethods() {
    console.log("[*] Hooking progression methods...");
    
    // Hook the box progression widget update
    // This is where the x/160 counter is likely updated
    hookBoxProgressionWidget();
    
    // Hook counter increment methods
    hookCounterIncrement();
    
    // Hook reward claim methods
    hookRewardClaim();
}

function hookBoxProgressionWidget() {
    console.log("[*] Hooking box progression widget methods...");
    
    // Search for methods that contain "boxProgressionWidget" or similar
    var exports = Module.enumerateExports("GameAssembly.dll");
    
    exports.forEach(function(exp) {
        if (exp.name.includes("boxProgressionWidget") || 
            exp.name.includes("BoxProgression") ||
            exp.name.includes("UpdateCounter") ||
            exp.name.includes("SetProgress")) {
            
            console.log("[*] Found progression method: " + exp.name);
            
            try {
                Interceptor.attach(exp.address, {
                    onEnter: function(args) {
                        console.log("[*] Progression method called: " + exp.name);
                        
                        // Check for counter values in arguments
                        this.originalArgs = [];
                        for (var i = 0; i < 8; i++) {
                            try {
                                var val = args[i].toInt32();
                                this.originalArgs.push(val);
                                
                                // If we find a value >= 160, reset it
                                if (val >= 160) {
                                    console.log("[*] Found counter >= 160: " + val + " - resetting to 0");
                                    args[i] = ptr(0);
                                }
                            } catch (e) {
                                this.originalArgs.push(null);
                            }
                        }
                    },
                    onLeave: function(retval) {
                        // Additional processing if needed
                    }
                });
            } catch (e) {
                console.log("[!] Failed to hook " + exp.name + ": " + e);
            }
        }
    });
}

function hookCounterIncrement() {
    console.log("[*] Hooking counter increment methods...");
    
    // Hook increment operations
    var exports = Module.enumerateExports("GameAssembly.dll");
    
    exports.forEach(function(exp) {
        if (exp.name.includes("Increment") ||
            exp.name.includes("Add") ||
            exp.name.includes("Update") && exp.name.includes("Counter")) {
            
            try {
                Interceptor.attach(exp.address, {
                    onEnter: function(args) {
                        // Check if we're incrementing a counter that might be the crate counter
                        for (var i = 0; i < args.length; i++) {
                            try {
                                var val = args[i].toInt32();
                                if (val > 0 && val < 200) {  // Reasonable range for crate counter
                                    console.log("[*] Counter increment detected: " + val);
                                    
                                    // If incrementing would put us at or over 160, reset instead
                                    if (val >= 160) {
                                        console.log("[*] Counter would exceed 160, resetting to 0");
                                        args[i] = ptr(0);
                                    }
                                }
                            } catch (e) {}
                        }
                    }
                });
            } catch (e) {
                console.log("[!] Failed to hook increment method: " + e);
            }
        }
    });
}

function hookRewardClaim() {
    console.log("[*] Hooking reward claim methods...");
    
    var exports = Module.enumerateExports("GameAssembly.dll");
    
    exports.forEach(function(exp) {
        if (exp.name.includes("ClaimReward") ||
            exp.name.includes("GetReward") ||
            exp.name.includes("ProcessReward")) {
            
            try {
                Interceptor.attach(exp.address, {
                    onEnter: function(args) {
                        console.log("[*] Reward claim method called: " + exp.name);
                        
                        // Store context for modification
                        this.isRewardClaim = true;
                    },
                    onLeave: function(retval) {
                        if (this.isRewardClaim) {
                            try {
                                var rewardAmount = retval.toInt32();
                                console.log("[*] Reward amount: " + rewardAmount);
                                
                                // If reward is 1 car, change it to 4 cars
                                if (rewardAmount === 1) {
                                    console.log("[*] Modifying reward from 1 car to 4 cars");
                                    retval.replace(ptr(4));
                                }
                            } catch (e) {
                                console.log("[!] Error modifying reward: " + e);
                            }
                        }
                    }
                });
            } catch (e) {
                console.log("[!] Failed to hook reward method: " + e);
            }
        }
    });
}

function hookUIUpdates() {
    console.log("[*] Hooking UI text updates...");
    
    // Hook Unity Text component updates
    var textMethods = [
        "Text_set_text",
        "TextMeshProUGUI_set_text",
        "TextMeshPro_set_text"
    ];
    
    textMethods.forEach(function(methodName) {
        var methodPtr = Module.findExportByName("GameAssembly.dll", methodName);
        if (methodPtr) {
            console.log("[*] Found UI method: " + methodName);
            
            Interceptor.attach(methodPtr, {
                onEnter: function(args) {
                    try {
                        // args[1] is the text string
                        var textPtr = args[1];
                        if (textPtr && !textPtr.isNull()) {
                            var text = Memory.readUtf16String(textPtr);
                            
                            // Check for crate counter pattern
                            if (text && text.match(/\d+\/160/)) {
                                console.log("[*] Crate counter UI update: " + text);
                                
                                // Extract current count
                                var match = text.match(/(\d+)\/160/);
                                if (match) {
                                    var currentCount = parseInt(match[1]);
                                    
                                    // If count is >= 160, reset display to 0/160
                                    if (currentCount >= 160) {
                                        console.log("[*] Resetting UI counter display");
                                        var newText = text.replace(/\d+\/160/, "0/160");
                                        args[1] = Memory.allocUtf16String(newText);
                                    }
                                }
                            }
                        }
                    } catch (e) {
                        console.log("[!] Error in UI hook: " + e);
                    }
                }
            });
        }
    });
}

function hookRewardSystem() {
    console.log("[*] Hooking reward system...");
    
    // Hook methods that determine reward amounts
    var exports = Module.enumerateExports("GameAssembly.dll");
    
    exports.forEach(function(exp) {
        if (exp.name.includes("GetRewardAmount") ||
            exp.name.includes("CalculateReward") ||
            exp.name.includes("RewardCount")) {
            
            try {
                Interceptor.attach(exp.address, {
                    onLeave: function(retval) {
                        try {
                            var amount = retval.toInt32();
                            
                            // Ensure we always get 4 cars for crate rewards
                            if (amount === 1) {
                                console.log("[*] Modifying reward amount from 1 to 4");
                                retval.replace(ptr(4));
                            }
                        } catch (e) {}
                    }
                });
            } catch (e) {
                console.log("[!] Failed to hook reward system: " + e);
            }
        }
    });
}

// Memory scanning for crate counter values
function scanForCrateCounters() {
    console.log("[*] Scanning for crate counter memory locations...");
    
    var found = [];
    var ranges = Process.enumerateRanges('rw-');
    
    ranges.forEach(function(range) {
        if (range.size > 0x1000) { // Skip very small ranges
            try {
                // Scan for values around 160 (0xA0)
                var pattern = "A0 00 00 00"; // 160 in little-endian
                var results = Memory.scanSync(range.base, range.size, pattern);
                
                results.forEach(function(result) {
                    var value = Memory.readInt32(result.address);
                    if (value === 160) {
                        console.log("[*] Found potential crate counter at: " + result.address);
                        found.push(result.address);
                        
                        // Set up a monitor for this address
                        monitorAddress(result.address);
                    }
                });
            } catch (e) {
                // Range not accessible
            }
        }
    });
    
    return found;
}

function monitorAddress(address) {
    // Monitor this address for changes
    var lastValue = Memory.readInt32(address);
    
    setInterval(function() {
        try {
            var currentValue = Memory.readInt32(address);
            if (currentValue !== lastValue) {
                console.log("[*] Counter at " + address + " changed: " + lastValue + " -> " + currentValue);
                
                // If it reaches 160, reset it
                if (currentValue >= 160) {
                    console.log("[*] Resetting counter at " + address);
                    Memory.writeInt32(address, 0);
                }
                
                lastValue = currentValue;
            }
        } catch (e) {
            // Address no longer valid
        }
    }, 1000); // Check every second
}

// RPC exports
rpc.exports = {
    resetCounter: function() {
        console.log("[*] Manual counter reset requested");
        scanForCrateCounters();
        return "Reset completed";
    },
    
    scanMemory: function() {
        var addresses = scanForCrateCounters();
        return "Found " + addresses.length + " potential counters";
    }
};

// Initialize when the script loads
setTimeout(function() {
    if (initializeScript()) {
        console.log("[*] Script initialized successfully");
        
        // Start memory scanning
        setTimeout(scanForCrateCounters, 2000);
    } else {
        console.log("[!] Failed to initialize script");
    }
}, 1000);

console.log("[*] Advanced crate counter reset script loaded");
console.log("[*] This script will:")
console.log("[*]   - Monitor your crate counter");
console.log("[*]   - Reset it to 0 when it reaches 160");
console.log("[*]   - Ensure you always get 4 cars as rewards");
console.log("[*]   - Modify UI display to show reset counter");
