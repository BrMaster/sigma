#!/usr/bin/env python3
"""
Analyzer for trueorfalse.py - CTF challenge "To True or Not To True"
This script deobfuscates and analyzes the trueorfalse.py file.

Run: python3 analyze.py
"""
import sys
import os
import types
import io

# ===== STEP 1: Understand the obfuscation =====
# The code uses Chinese characters as variable names and True+True+... to represent numbers
# True in Python == 1, so (True)+(True)+(True) == 3
# The lambda on line 2 converts numbers to characters via chr()
# Line 1: 星要行以可和可国要和作 = ord  (assigns ord function)
# Line 2: lambda that joins chr() of given numbers -> builds strings
# Lines 3-6: getattr(__builtins__, ...) -> getting built-in functions by constructing their names

print("="*60)
print("TRUEORFALSE.PY ANALYZER")
print("="*60)

# ===== STEP 2: Try to intercept exec/eval calls =====
# Most obfuscated CTF challenges eventually call exec() or eval()
# We'll monkey-patch them to capture the deobfuscated code

captured_code = []
original_exec = exec
original_eval = eval
original_print = print

def fake_exec(code, *args, **kwargs):
    if isinstance(code, str):
        captured_code.append(("exec", code))
        original_print(f"\n[CAPTURED exec() call - {len(code)} chars]")
        # If the code itself contains more exec/eval, keep going
        if 'exec' in code or 'eval' in code:
            original_print("[Contains nested exec/eval, going deeper...]")
            try:
                original_exec(code, *args, **kwargs)
            except Exception as e:
                original_print(f"[Nested execution error: {e}]")
        else:
            original_print("[Final deobfuscated code:]")
            original_print(code[:5000])
    elif isinstance(code, bytes):
        captured_code.append(("exec_bytes", code))
        original_print(f"\n[CAPTURED exec() call with bytes - {len(code)} bytes]")
        try:
            decoded = code.decode('utf-8', errors='replace')
            original_print(decoded[:5000])
        except:
            original_print(code[:5000])
    elif isinstance(code, types.CodeType):
        captured_code.append(("exec_code", code))
        original_print(f"\n[CAPTURED exec() call with code object]")
        original_print(f"  co_consts: {code.co_consts}")
        original_print(f"  co_names: {code.co_names}")
        # Try to execute it anyway
        try:
            original_exec(code, *args, **kwargs)
        except Exception as e:
            original_print(f"  [Execution error: {e}]")

def fake_eval(code, *args, **kwargs):
    if isinstance(code, str):
        captured_code.append(("eval", code))
        original_print(f"\n[CAPTURED eval() call - {len(code)} chars]")
        original_print(code[:5000])
    try:
        return original_eval(code, *args, **kwargs)
    except:
        return None

# ===== STEP 3: Try to read and analyze the file =====
script_dir = os.path.dirname(os.path.abspath(__file__))
target = os.path.join(script_dir, "trueorfalse.py")

if not os.path.exists(target):
    original_print(f"ERROR: {target} not found!")
    sys.exit(1)

original_print(f"\nReading {target}...")
with open(target, 'r', encoding='utf-8') as f:
    content = f.read()

original_print(f"File size: {len(content)} characters")
original_print(f"Number of lines: {content.count(chr(10)) + 1}")

# ===== STEP 4: Quick static analysis =====
original_print("\n" + "="*60)
original_print("STATIC ANALYSIS")
original_print("="*60)

# Check for common patterns
for keyword in ['exec', 'eval', 'compile', 'base64', 'zlib', 'marshal',
                'input', 'flag', 'SK-CERT', 'print', '__import__', 'decode']:
    count = content.count(keyword)
    if count > 0:
        original_print(f"  Found '{keyword}': {count} occurrences")

# Show first few lines decoded
original_print("\n" + "="*60)
original_print("FIRST 10 LINES (raw)")
original_print("="*60)
for i, line in enumerate(content.split('\n')[:10], 1):
    original_print(f"  Line {i}: {line[:200]}...")

# ===== STEP 5: Manually decode the True-based numbers =====
original_print("\n" + "="*60)
original_print("DECODING True-BASED OBFUSCATION")
original_print("="*60)

# Line 1: ord is assigned
# Line 2: lambda that does "".join(map(chr, numbers)) - converts numbers to string
# So the pattern (True)+(True)+... = counting Trues gives us a number
# Then chr(number) gives us a character

# Let's try to safely execute with intercepted exec/eval
original_print("\n" + "="*60)
original_print("DYNAMIC ANALYSIS - Intercepting exec/eval")  
original_print("="*60)

import builtins
builtins.exec = fake_exec
builtins.eval = fake_eval

# Also intercept input() to prevent hanging
def fake_input(prompt=""):
    original_print(f"\n[INTERCEPTED input() call with prompt: {prompt}]")
    return "test_flag_input"
builtins.input = fake_input

try:
    # Compile and run with our patched builtins
    code = compile(content, 'trueorfalse.py', 'exec')
    original_exec(code, {'__builtins__': builtins, '__name__': '__main__'})
except SystemExit:
    original_print("\n[Program tried to exit]")
except Exception as e:
    original_print(f"\n[Error during execution: {type(e).__name__}: {e}]")

# ===== STEP 6: Summary =====
original_print("\n" + "="*60)
original_print("SUMMARY")
original_print("="*60)
original_print(f"Total captured exec/eval calls: {len(captured_code)}")
for i, (call_type, code) in enumerate(captured_code):
    original_print(f"\n--- Captured call #{i+1} ({call_type}) ---")
    if isinstance(code, str):
        original_print(code[:10000])
    elif isinstance(code, bytes):
        original_print(code[:10000])
    else:
        original_print(str(code))

# Restore
builtins.exec = original_exec
builtins.eval = original_eval
builtins.input = input

original_print("\n" + "="*60)
original_print("DONE - Check output above for the flag!")
original_print("="*60)