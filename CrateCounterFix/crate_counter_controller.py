#!/usr/bin/env python3
"""
Drive Zone Online Crate Counter Reset Controller
Uses Frida to hook into the game and reset crate counters at 100 to maintain proper rewards
Based on GameGuardian pattern: 1,514Q;200~80000Q;1,514Q;200~80000::25
FIXED: 300/100 = 3 cars, not 1 car (proper reward calculation)
"""

import frida
import sys
import time
import json

class CrateCounterController:
    def __init__(self):
        self.device = None
        self.session = None
        self.script = None
        self.process_name = "Drive Zone Online"
        self.current_count = 0
        self.script_type = "basic"  # "basic", "advanced", or "gameguardian"
        
    def connect_to_device(self):
        """Connect to USB device or local machine"""
        try:
            # Try USB device first
            self.device = frida.get_usb_device()
            print("[*] Connected to USB device")
        except frida.InvalidArgumentError:
            # Fallback to local device
            self.device = frida.get_local_device()
            print("[*] Connected to local device")
        
    def find_drive_zone_process(self):
        """Find the Drive Zone Online process"""
        processes = self.device.enumerate_processes()
        
        print("[*] Looking for Drive Zone Online process...")
        for process in processes:
            if "drive" in process.name.lower() or "zone" in process.name.lower():
                print(f"[*] Found potential process: {process.name} (PID: {process.pid})")
                self.process_name = process.name
                return process.pid
                
        # List all processes if not found
        print("[*] Drive Zone process not found. Available processes:")
        for process in processes:
            print(f"  - {process.name} (PID: {process.pid})")
        
        return None
    
    def choose_script_type(self):
        """Let user choose which script to use"""
        print("\nChoose script type:")
        print("1. Basic Counter Reset (crate_counter_reset.js)")
        print("2. Advanced IL2CPP Targeting (advanced_crate_reset.js)")
        print("3. GameGuardian Pattern Hook (gameguardian_pattern_hook.js)")
        print("4. Direct Memory Patcher (il2cpp_memory_patcher.js)")
        
        while True:
            try:
                choice = input("Select script (1-4): ").strip()
                if choice == "1":
                    self.script_type = "basic"
                    return "crate_counter_reset.js"
                elif choice == "2":
                    self.script_type = "advanced"
                    return "advanced_crate_reset.js"
                elif choice == "3":
                    self.script_type = "gameguardian"
                    return "gameguardian_pattern_hook.js"
                elif choice == "4":
                    self.script_type = "memory_patcher"
                    return "il2cpp_memory_patcher.js"
                else:
                    print("Please enter 1, 2, 3, or 4")
            except KeyboardInterrupt:
                return None
    
    def load_hook_script(self):
        """Load the selected Frida JavaScript hook"""
        script_name = self.choose_script_type()
        if not script_name:
            return None
            
        try:
            with open(script_name, 'r') as f:
                script_content = f.read()
            print(f"[*] Loaded script: {script_name}")
            return script_content
        except FileNotFoundError:
            print(f"[!] Script file not found: {script_name}")
            return None
    
    def attach_to_process(self, pid):
        """Attach to the game process and inject hooks"""
        try:
            self.session = self.device.attach(pid)
            script_content = self.load_hook_script()
            
            self.script = self.session.create_script(script_content)
            self.script.on('message', self.on_message)
            self.script.load()
            
            print(f"[*] Successfully attached to process {pid}")
            return True
            
        except Exception as e:
            print(f"[!] Failed to attach: {e}")
            return False
    
    def on_message(self, message, data):
        """Handle messages from the Frida script"""
        if message['type'] == 'send':
            print(f"[SCRIPT] {message['payload']}")
        elif message['type'] == 'error':
            print(f"[ERROR] {message['stack']}")
    
    def reset_crate_counter(self):
        """Manually reset the crate counter"""
        if self.script:
            try:
                if self.script_type == "gameguardian":
                    result = self.script.exports.reset_all_counters()
                else:
                    result = self.script.exports.reset_crate_counter()
                print(f"[*] Counter reset result: {result}")
                return result
            except Exception as e:
                print(f"[!] Failed to reset counter: {e}")
                return None
    
    def get_crate_count(self):
        """Get current crate count"""
        if self.script:
            try:
                if self.script_type == "gameguardian":
                    counters = self.script.exports.get_counters()
                    print(f"[*] Current counters: {counters}")
                    return counters
                else:
                    count = self.script.exports.get_crate_count()
                    print(f"[*] Current crate count: {count}")
                    return count
            except Exception as e:
                print(f"[!] Failed to get count: {e}")
                return None
    
    def get_patterns(self):
        """Get GameGuardian patterns (only for gameguardian script)"""
        if self.script and self.script_type == "gameguardian":
            try:
                patterns = self.script.exports.get_patterns()
                print(f"[*] Found patterns: {patterns}")
                return patterns
            except Exception as e:
                print(f"[!] Failed to get patterns: {e}")
                return None
    
    def scan_pattern(self):
        """Scan for GameGuardian pattern"""
        if self.script:
            try:
                if self.script_type == "gameguardian":
                    result = self.script.exports.scan_pattern()
                elif hasattr(self.script.exports, 'search_game_guardian_pattern'):
                    result = self.script.exports.search_game_guardian_pattern()
                else:
                    result = self.script.exports.scan_counters()
                print(f"[*] Pattern scan result: {result}")
                return result
            except Exception as e:
                print(f"[!] Failed to scan pattern: {e}")
                return None
    
    def set_max_crate_count(self, max_count):
        """Set maximum crate count before reset"""
        if self.script:
            try:
                result = self.script.exports.set_max_crate_count(max_count)
                print(f"[*] Max count set result: {result}")
                return result
            except Exception as e:
                print(f"[!] Failed to set max count: {e}")
                return None
    
    def set_spin_values(self, normal, lag):
        """Set spin values (for GameGuardian script)"""
        if self.script and self.script_type == "gameguardian":
            try:
                result = self.script.exports.set_spin_values(normal, lag)
                print(f"[*] Spin values set result: {result}")
                return result
            except Exception as e:
                print(f"[!] Failed to set spin values: {e}")
                return None
    
    def scan_counters(self):
        """Scan for crate counter memory locations"""
        if self.script:
            try:
                result = self.script.exports.scan_counters()
                print(f"[*] Scan result: {result}")
                return result
            except Exception as e:
                print(f"[!] Failed to scan: {e}")
                return None
    
    def interactive_mode(self):
        """Interactive mode for crate counter management"""
        print("\n[*] Entering interactive mode. Commands:")
        print("  status - Show current crate count/counters")
        print("  reset - Manually reset crate counter")
        print("  scan - Scan for counter memory locations")
        print("  pattern - Scan for GameGuardian pattern")
        print("  patterns - Show found GameGuardian patterns")
        print("  max <number> - Set maximum count before auto-reset")
        print("  spin <normal> <lag> - Set spin values (GameGuardian only)")
        print("  quit - Exit")
        print(f"\n[*] Using script type: {self.script_type}")
        print("[*] The script will automatically reset your counter at 100 to maintain proper rewards")
        
        while True:
            try:
                cmd = input(f"\n[{self.script_type}]CrateCounter> ").strip().split()
                
                if not cmd:
                    continue
                    
                if cmd[0] == "quit":
                    break
                elif cmd[0] == "status":
                    count = self.get_crate_count()
                    if count is not None:
                        if self.script_type == "gameguardian":
                            print(f"[*] Current counters: {count}")
                        else:
                            print(f"[*] Current crate count: {count}/100")
                            if count >= 100:
                                print("[!] WARNING: Counter is at or above 100 - triggering reset for proper rewards!")
                elif cmd[0] == "reset":
                    self.reset_crate_counter()
                    print("[*] Manual reset completed")
                elif cmd[0] == "scan":
                    self.scan_counters()
                    print("[*] Memory scan completed")
                elif cmd[0] == "pattern":
                    self.scan_pattern()
                    print("[*] Pattern scan completed")
                elif cmd[0] == "patterns":
                    patterns = self.get_patterns()
                    if patterns:
                        print(f"[*] Found patterns: {len(patterns)}")
                        for i, pattern in enumerate(patterns):
                            print(f"  Pattern {i+1}: {pattern}")
                elif cmd[0] == "max" and len(cmd) >= 2:
                    try:
                        max_count = int(cmd[1])
                        self.set_max_crate_count(max_count)
                        print(f"[*] Max count set to {max_count}")
                    except ValueError:
                        print("[!] Invalid number")
                elif cmd[0] == "spin" and len(cmd) >= 3:
                    try:
                        normal = int(cmd[1])
                        lag = int(cmd[2])
                        self.set_spin_values(normal, lag)
                        print(f"[*] Spin values set to {normal} (normal), {lag} (lag)")
                    except ValueError:
                        print("[!] Invalid numbers")
                else:
                    print("[!] Unknown command")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] Error: {e}")
    
    def monitor_mode(self):
        """Monitor mode - continuously check and reset counter"""
        print("\n[*] Entering monitor mode...")
        print(f"[*] Using script type: {self.script_type}")
        print("[*] The script will monitor your crate counter and auto-reset at 100")
        print("[*] Press Ctrl+C to stop monitoring")
        
        try:
            while True:
                if self.script_type == "gameguardian":
                    counters = self.get_crate_count()
                    if counters:
                        for address, value in counters.items():
                            if isinstance(value, int) and value >= 100:
                                print(f"[!] Counter at {address} reached {value} - triggering reset")
                                self.reset_crate_counter()
                                break
                else:
                    count = self.get_crate_count()
                    if count is not None and count >= 100:
                        print(f"[!] Counter at {count} - auto-resetting to maintain 4-car rewards")
                        self.reset_crate_counter()
                
                time.sleep(5)  # Check every 5 seconds
                
        except KeyboardInterrupt:
            print("\n[*] Monitor mode stopped")

def main():
    controller = CrateCounterController()
    
    print("=" * 60)
    print("Drive Zone Online - Crate Counter Reset Controller")
    print("=" * 60)
    print("[*] This script will help you maintain 4-car rewards by resetting")
    print("[*] your crate counter when it reaches 100 (instead of going beyond)")
    print("[*] FIXED: 300/100 = 3 cars, not 1 car (proper reward calculation)")
    print("[*] Based on GameGuardian pattern: 1,514Q;200~80000Q;1,514Q;200~80000::25")
    print("[*] Handles spin values of 30 (normal) and 29 (with lag)")
    print("=" * 60)
    
    # Connect to device
    controller.connect_to_device()
    
    # Find the game process
    pid = controller.find_drive_zone_process()
    if not pid:
        print("[!] Please start Drive Zone Online and try again")
        return
    
    # Attach and inject hooks
    if controller.attach_to_process(pid):
        print("[*] Hooks injected successfully!")
        print("[*] The script is now monitoring your crate counter")
        
        # Wait a moment for hooks to stabilize
        time.sleep(3)
        
        # Ask user for mode preference
        print("\nSelect mode:")
        print("1. Interactive mode (manual control)")
        print("2. Monitor mode (automatic reset)")
        
        while True:
            try:
                choice = input("Choose mode (1 or 2): ").strip()
                if choice == "1":
                    controller.interactive_mode()
                    break
                elif choice == "2":
                    controller.monitor_mode()
                    break
                else:
                    print("Please enter 1 or 2")
            except KeyboardInterrupt:
                break
    
    print("[*] Cleaning up...")

if __name__ == "__main__":
    main()
