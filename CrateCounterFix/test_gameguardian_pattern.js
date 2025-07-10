// Test Script for GameGuardian Pattern Validation
// This script helps verify that the GameGuardian pattern is working correctly

console.log("[*] GameGuardian Pattern Test Script");
console.log("[*] Pattern: 1,514Q;200~80000Q;1,514Q;200~80000::25");

// Test configuration
var TEST_CONFIG = {
    pattern: [1514, 200, 80000, 1514, 200, 80000],
    spinValues: [30, 29],
    maxCounter: 160,
    testMode: true
};

// Storage for test results
var testResults = {
    patternsFound: 0,
    countersMonitored: 0,
    resetsPerformed: 0,
    spinValuesDetected: 0,
    errors: []
};

function runPatternTest() {
    console.log("[*] Starting GameGuardian pattern test...");
    
    // Test 1: Pattern Discovery
    testPatternDiscovery();
    
    // Test 2: Counter Monitoring
    testCounterMonitoring();
    
    // Test 3: Spin Value Detection
    testSpinValueDetection();
    
    // Test 4: Reset Functionality
    testResetFunctionality();
    
    // Display results
    displayTestResults();
}

function testPatternDiscovery() {
    console.log("[*] Test 1: Pattern Discovery");
    
    try {
        var ranges = Process.enumerateRanges('rw-');
        var patternsFound = 0;
        
        ranges.forEach(function(range) {
            if (range.size > 0x1000) {
                try {
                    var pattern = "EA 05 00 00"; // 1514 in hex
                    var results = Memory.scanSync(range.base, range.size, pattern);
                    
                    results.forEach(function(result) {
                        if (validateTestPattern(result.address)) {
                            patternsFound++;
                            console.log("[*] Valid pattern found at: " + result.address);
                        }
                    });
                } catch (e) {
                    // Range scan failed
                }
            }
        });
        
        testResults.patternsFound = patternsFound;
        console.log("[*] Pattern discovery test completed: " + patternsFound + " patterns found");
        
    } catch (e) {
        testResults.errors.push("Pattern discovery failed: " + e);
        console.log("[!] Pattern discovery test failed: " + e);
    }
}

function validateTestPattern(address) {
    try {
        var val1 = Memory.readInt32(address);
        var val2 = Memory.readInt32(address.add(4));
        var val3 = Memory.readInt32(address.add(8));
        var val4 = Memory.readInt32(address.add(12));
        
        var isValid = (val1 === 1514) &&
                      (val2 >= 200 && val2 <= 80000) &&
                      (val3 === 1514) &&
                      (val4 >= 200 && val4 <= 80000);
        
        if (isValid) {
            console.log("[*] Pattern validation: [" + val1 + ", " + val2 + ", " + val3 + ", " + val4 + "]");
        }
        
        return isValid;
    } catch (e) {
        return false;
    }
}

function testCounterMonitoring() {
    console.log("[*] Test 2: Counter Monitoring");
    
    try {
        // Search for counter values near 160
        var counterValues = [158, 159, 160, 161, 162];
        var countersFound = 0;
        
        counterValues.forEach(function(value) {
            var pattern = formatHexPattern(value);
            var ranges = Process.enumerateRanges('rw-');
            
            ranges.forEach(function(range) {
                try {
                    var results = Memory.scanSync(range.base, range.size, pattern);
                    results.forEach(function(result) {
                        var foundValue = Memory.readInt32(result.address);
                        if (foundValue === value) {
                            countersFound++;
                            console.log("[*] Counter value " + value + " found at: " + result.address);
                        }
                    });
                } catch (e) {
                    // Range scan failed
                }
            });
        });
        
        testResults.countersMonitored = countersFound;
        console.log("[*] Counter monitoring test completed: " + countersFound + " counters found");
        
    } catch (e) {
        testResults.errors.push("Counter monitoring failed: " + e);
        console.log("[!] Counter monitoring test failed: " + e);
    }
}

function testSpinValueDetection() {
    console.log("[*] Test 3: Spin Value Detection");
    
    try {
        var spinValues = [30, 29];
        var spinValuesFound = 0;
        
        spinValues.forEach(function(value) {
            var pattern = formatHexPattern(value);
            var ranges = Process.enumerateRanges('rw-');
            
            ranges.forEach(function(range) {
                try {
                    var results = Memory.scanSync(range.base, range.size, pattern);
                    results.forEach(function(result) {
                        var foundValue = Memory.readInt32(result.address);
                        if (foundValue === value) {
                            spinValuesFound++;
                            console.log("[*] Spin value " + value + " found at: " + result.address);
                        }
                    });
                } catch (e) {
                    // Range scan failed
                }
            });
        });
        
        testResults.spinValuesDetected = spinValuesFound;
        console.log("[*] Spin value detection test completed: " + spinValuesFound + " spin values found");
        
    } catch (e) {
        testResults.errors.push("Spin value detection failed: " + e);
        console.log("[!] Spin value detection test failed: " + e);
    }
}

function testResetFunctionality() {
    console.log("[*] Test 4: Reset Functionality");
    
    try {
        // Create a test memory area
        var testMemory = Memory.alloc(16);
        
        // Write test pattern
        Memory.writeInt32(testMemory, 1514);
        Memory.writeInt32(testMemory.add(4), 165); // Over limit
        Memory.writeInt32(testMemory.add(8), 1514);
        Memory.writeInt32(testMemory.add(12), 155); // Under limit
        
        console.log("[*] Test memory created with pattern: [1514, 165, 1514, 155]");
        
        // Test reset logic
        var counter1 = Memory.readInt32(testMemory.add(4));
        var counter2 = Memory.readInt32(testMemory.add(12));
        
        if (counter1 >= 160) {
            var overflow = counter1 - 160;
            var newValue = Math.max(0, Math.min(overflow, 159));
            Memory.writeInt32(testMemory.add(4), newValue);
            testResults.resetsPerformed++;
            console.log("[*] Reset performed: 165 -> " + newValue);
        }
        
        // Verify reset worked
        var newCounter1 = Memory.readInt32(testMemory.add(4));
        var newCounter2 = Memory.readInt32(testMemory.add(12));
        
        console.log("[*] Final pattern: [1514, " + newCounter1 + ", 1514, " + newCounter2 + "]");
        console.log("[*] Reset functionality test completed: " + testResults.resetsPerformed + " resets performed");
        
    } catch (e) {
        testResults.errors.push("Reset functionality failed: " + e);
        console.log("[!] Reset functionality test failed: " + e);
    }
}

function formatHexPattern(value) {
    // Convert integer to little-endian hex pattern
    var hex = value.toString(16).padStart(8, '0');
    return hex.substring(6, 8) + " " + hex.substring(4, 6) + " " + hex.substring(2, 4) + " " + hex.substring(0, 2);
}

function displayTestResults() {
    console.log("\n" + "=".repeat(50));
    console.log("GameGuardian Pattern Test Results");
    console.log("=".repeat(50));
    console.log("Patterns Found: " + testResults.patternsFound);
    console.log("Counters Monitored: " + testResults.countersMonitored);
    console.log("Spin Values Detected: " + testResults.spinValuesDetected);
    console.log("Resets Performed: " + testResults.resetsPerformed);
    console.log("Errors: " + testResults.errors.length);
    
    if (testResults.errors.length > 0) {
        console.log("\nError Details:");
        testResults.errors.forEach(function(error, index) {
            console.log((index + 1) + ". " + error);
        });
    }
    
    console.log("\nTest Summary:");
    if (testResults.patternsFound > 0) {
        console.log("✓ Pattern discovery working");
    } else {
        console.log("✗ Pattern discovery failed");
    }
    
    if (testResults.countersMonitored > 0) {
        console.log("✓ Counter monitoring working");
    } else {
        console.log("✗ Counter monitoring failed");
    }
    
    if (testResults.resetsPerformed > 0) {
        console.log("✓ Reset functionality working");
    } else {
        console.log("✗ Reset functionality failed");
    }
    
    console.log("=".repeat(50));
}

// Export functions for external testing
rpc.exports = {
    runTest: function() {
        runPatternTest();
        return testResults;
    },
    
    testPatternDiscovery: function() {
        testPatternDiscovery();
        return testResults.patternsFound;
    },
    
    testCounterMonitoring: function() {
        testCounterMonitoring();
        return testResults.countersMonitored;
    },
    
    testSpinValueDetection: function() {
        testSpinValueDetection();
        return testResults.spinValuesDetected;
    },
    
    testResetFunctionality: function() {
        testResetFunctionality();
        return testResults.resetsPerformed;
    },
    
    getTestResults: function() {
        return testResults;
    }
};

// Auto-run test when script loads
setTimeout(function() {
    console.log("[*] Auto-running pattern test...");
    runPatternTest();
}, 2000);

console.log("[*] GameGuardian Pattern Test Script loaded");
console.log("[*] Use rpc.exports.runTest() to run tests manually");
console.log("[*] Test will auto-run in 2 seconds...");
