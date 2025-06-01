import argparse
import json
import os
import base64
import itertools # For brute-forcing combinations
import sys      # For sys.stdout.write and flush
import time     # For timing

# --- CRC32 Constants (Standard Ethernet/PKZIP/PNG) ---
CRC32_POLY_REFLECTED = 0xEDB88320
CRC32_INIT = 0xFFFFFFFF
CRC32_XOR_OUT = 0xFFFFFFFF
HINT_SUFFIX_LENGTH = 8 # The hint is the last 8 bytes

# --- CRC32 Calculation Functions ---
def _crc32_core(data_bytes, initial_crc_val):
    crc = initial_crc_val
    for byte_val in data_bytes: # Iterate over integer values of bytes
        crc ^= byte_val
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ CRC32_POLY_REFLECTED
            else:
                crc = crc >> 1
    return crc

def calculate_crc32_final_from_bytes(data_bytes):
    """Calculates final CRC32 for given bytes."""
    raw_crc = _crc32_core(data_bytes, CRC32_INIT)
    return raw_crc ^ CRC32_XOR_OUT

def calculate_crc32_for_file(filepath):
    """Calculates CRC32 for an entire file, reading in chunks."""
    try:
        current_crc = CRC32_INIT
        with open(filepath, 'rb') as f:
            while True:
                data_chunk = f.read(4096)
                if not data_chunk:
                    break
                current_crc = _crc32_core(data_chunk, current_crc)
        return current_crc ^ CRC32_XOR_OUT
    except FileNotFoundError:
        # This will be handled by the calling function
        raise
    except Exception as e:
        print(f"Error calculating CRC for '{filepath}': {e}")
        return None

# --- Main Operations ---

def prepare_compressed_file(original_filepath, compressed_filepath):
    """
    Reads the original file, calculates its CRC32, extracts the last
    HINT_SUFFIX_LENGTH bytes as a hint, and saves these to the compressed_filepath.
    """
    try:
        original_file_size = os.path.getsize(original_filepath)
    except FileNotFoundError:
        print(f"Error: Original file '{original_filepath}' not found.")
        return

    if original_file_size < HINT_SUFFIX_LENGTH:
        print(f"Error: Original file is too small (less than {HINT_SUFFIX_LENGTH} bytes).")
        return

    print(f"Processing '{original_filepath}' for 'compression'...")
    
    target_crc = calculate_crc32_for_file(original_filepath)
    if target_crc is None:
        return # Error already printed by calculate_crc32_for_file

    hint_suffix_bytes = b''
    with open(original_filepath, 'rb') as f:
        f.seek(original_file_size - HINT_SUFFIX_LENGTH)
        hint_suffix_bytes = f.read(HINT_SUFFIX_LENGTH)

    compressed_data_dict = {
        "target_crc32_hex": f"{target_crc:08X}",
        "hint_suffix_base64": base64.b64encode(hint_suffix_bytes).decode('utf-8'),
        "hint_suffix_length": HINT_SUFFIX_LENGTH,
        "original_file_size": original_file_size  # Added for verification
    }

    try:
        with open(compressed_filepath, 'w') as cf:
            json.dump(compressed_data_dict, cf, indent=4)
        print(f"'Compressed' file (CRC and hint) saved to '{compressed_filepath}'.")
        print(f"  Original File Size: {original_file_size} bytes")
        print(f"  Original File CRC32: 0x{target_crc:08X}")
        print(f"  Hint Suffix (last {HINT_SUFFIX_LENGTH} bytes): {hint_suffix_bytes.hex().upper()}")
    except IOError as e:
        print(f"Error writing compressed file '{compressed_filepath}': {e}")


def try_single_prefix_length(target_crc_val, hint_suffix_bytes, prefix_length, max_time_per_length=None):
    """
    Try brute-forcing a single prefix length.
    Returns (success, result_data, combinations_tried, time_elapsed)
    """
    total_combinations = 256 ** prefix_length
    print(f"\n🔍 Trying prefix length {prefix_length} ({total_combinations:,} combinations)")
    
    if max_time_per_length:
        print(f"   Time limit: {max_time_per_length} seconds")
    
    count = 0
    start_time = time.time()
    
    # Adjust progress reporting frequency based on search space size
    progress_interval = min(50000, max(1000, total_combinations // 100))
    
    # Generate all possible byte combinations for the prefix
    for prefix_tuple in itertools.product(range(256), repeat=prefix_length):
        candidate_prefix_bytes = bytes(prefix_tuple)
        test_data_bytes = candidate_prefix_bytes + hint_suffix_bytes
        
        calculated_crc = calculate_crc32_final_from_bytes(test_data_bytes)
        
        count += 1
        
        # Check time limit
        if max_time_per_length:
            elapsed = time.time() - start_time
            if elapsed > max_time_per_length:
                sys.stdout.write("\r" + " " * 80 + "\r")
                print(f"   ⏰ Time limit reached after {count:,} combinations")
                return False, None, count, elapsed
        
        # Progress updates
        if count % progress_interval == 0 or count <= 1000:
            elapsed = time.time() - start_time
            rate = count / elapsed if elapsed > 0 else 0
            percent = (count / total_combinations) * 100
            sys.stdout.write(f"\r   Progress: {count:,}/{total_combinations:,} ({percent:.1f}%) - {rate:.0f}/sec")
            sys.stdout.flush()

        if calculated_crc == target_crc_val:
            elapsed = time.time() - start_time
            sys.stdout.write("\r" + " " * 80 + "\r")
            return True, test_data_bytes, count, elapsed

    elapsed = time.time() - start_time
    sys.stdout.write("\r" + " " * 80 + "\r")
    print(f"   ❌ No solution found ({count:,} combinations in {elapsed:.1f}s)")
    return False, None, count, elapsed


def reconstruct_by_auto_increment(compressed_filepath, reconstructed_output_filepath, 
                                 start_prefix=1, max_prefix=6, max_time_per_length=None):
    """
    Automatically try different prefix lengths starting from start_prefix up to max_prefix.
    """
    try:
        with open(compressed_filepath, 'r') as cf:
            compressed_data_dict = json.load(cf)
    except FileNotFoundError:
        print(f"Error: 'Compressed' file '{compressed_filepath}' not found.")
        return
    except json.JSONDecodeError:
        print(f"Error: '{compressed_filepath}' is not a valid JSON hint file.")
        return
    except IOError as e:
        print(f"Error reading '{compressed_filepath}': {e}")
        return

    target_crc_hex = compressed_data_dict.get("target_crc32_hex")
    hint_suffix_base64 = compressed_data_dict.get("hint_suffix_base64")
    original_file_size = compressed_data_dict.get("original_file_size", "unknown")
    
    if not all([target_crc_hex, hint_suffix_base64]):
        print("Error: Compressed file is missing required data (target_crc32_hex, hint_suffix_base64).")
        return

    try:
        target_crc_val = int(target_crc_hex, 16)
        hint_suffix_bytes = base64.b64decode(hint_suffix_base64)
    except ValueError as e:
        print(f"Error decoding data from compressed file: {e}")
        return

    print(f"🚀 Auto-increment brute force reconstruction")
    print(f"   Target CRC32: 0x{target_crc_val:08X}")
    print(f"   Original file size: {original_file_size} bytes")
    print(f"   Known suffix ({len(hint_suffix_bytes)} bytes): {hint_suffix_bytes.hex().upper()}")
    print(f"   Will try prefix lengths: {start_prefix} to {max_prefix}")
    
    if isinstance(original_file_size, int):
        expected_prefix_len = original_file_size - len(hint_suffix_bytes)
        if expected_prefix_len > 0:
            print(f"   📊 Expected prefix length based on file size: {expected_prefix_len}")
    
    total_start_time = time.time()
    total_combinations_tried = 0
    
    # Try each prefix length
    for prefix_len in range(start_prefix, max_prefix + 1):
        if prefix_len <= 0:
            continue
            
        # Warn about large search spaces
        total_combinations = 256 ** prefix_len
        if prefix_len > 4:
            print(f"\n⚠️  Warning: Prefix length {prefix_len} = {total_combinations:,} combinations!")
            if not max_time_per_length:
                confirm = input("This could take a very long time. Continue? (yes/no): ").lower()
                if confirm != 'yes':
                    print("Skipping this prefix length.")
                    continue
        
        success, result_data, combinations_tried, time_elapsed = try_single_prefix_length(
            target_crc_val, hint_suffix_bytes, prefix_len, max_time_per_length
        )
        
        total_combinations_tried += combinations_tried
        
        if success:
            total_elapsed = time.time() - total_start_time
            prefix_bytes = result_data[:-len(hint_suffix_bytes)]
            
            print(f"\n🎉 SUCCESS! Solution found with prefix length {prefix_len}")
            print(f"   Prefix: {prefix_bytes.hex().upper()}")
            print(f"   Full data ({len(result_data)} bytes): {result_data.hex().upper()}")
            print(f"   Found after {combinations_tried:,} combinations in {time_elapsed:.1f}s")
            print(f"   Total search time: {total_elapsed:.1f}s, total combinations: {total_combinations_tried:,}")
            
            # Verify the CRC calculation
            verify_crc = calculate_crc32_final_from_bytes(result_data)
            print(f"   Verification - Calculated: 0x{verify_crc:08X}, Target: 0x{target_crc_val:08X}")
            
            try:
                with open(reconstructed_output_filepath, 'wb') as outf:
                    outf.write(result_data)
                print(f"   💾 Reconstructed data saved to '{reconstructed_output_filepath}'")
                return True
            except IOError as e:
                print(f"   Error writing file: {e}")
                return False
    
    # No solution found
    total_elapsed = time.time() - total_start_time
    print(f"\n❌ No solution found after trying prefix lengths {start_prefix}-{max_prefix}")
    print(f"   Total time: {total_elapsed:.1f}s, total combinations: {total_combinations_tried:,}")
    print(f"   Consider:")
    print(f"   - Increasing max prefix length (--max-prefix)")
    print(f"   - Checking if the hint file is correct")
    print(f"   - Verifying the original file wasn't corrupted")
    return False


def reconstruct_by_bruteforce(compressed_filepath, reconstructed_output_filepath, prefix_length_to_bruteforce):
    """
    Original single prefix length brute force (kept for compatibility)
    """
    # Just call the single prefix attempt
    try:
        with open(compressed_filepath, 'r') as cf:
            compressed_data_dict = json.load(cf)
        
        target_crc_val = int(compressed_data_dict.get("target_crc32_hex"), 16)
        hint_suffix_bytes = base64.b64decode(compressed_data_dict.get("hint_suffix_base64"))
        
        success, result_data, _, _ = try_single_prefix_length(target_crc_val, hint_suffix_bytes, prefix_length_to_bruteforce)
        
        if success:
            with open(reconstructed_output_filepath, 'wb') as outf:
                outf.write(result_data)
            print(f"Reconstructed data saved to '{reconstructed_output_filepath}'")
        
    except Exception as e:
        print(f"Error during reconstruction: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="A tool to 'compress' a file into its CRC32 and an 8-byte hint (suffix), "
                    "and 'decompress' by brute-forcing the prefix.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="mode", required=True, help="Operation mode")

    # Prepare mode
    parser_prepare = subparsers.add_parser("prepare", 
        help="Prepare a 'compressed' file (CRC32 and 8-byte suffix hint) from an original file."
    )
    parser_prepare.add_argument("original_file", help="Path to the original full data file.")
    parser_prepare.add_argument("compressed_file_output", help="Path to save the generated .crch file.")

    # Auto-increment reconstruct mode
    parser_auto = subparsers.add_parser("auto-reconstruct", 
        help="Automatically try different prefix lengths until solution is found."
    )
    parser_auto.add_argument("compressed_file_input", help="Path to the .crch file to use.")
    parser_auto.add_argument("reconstructed_file_output", help="Path to save the reconstructed data file.")
    parser_auto.add_argument("--start-prefix", type=int, default=1, 
        help="Starting prefix length to try (default: 1)")
    parser_auto.add_argument("--max-prefix", type=int, default=6, 
        help="Maximum prefix length to try (default: 6)")
    parser_auto.add_argument("--max-time", type=int, default=None,
        help="Maximum time in seconds to spend on each prefix length")

    # Original single prefix reconstruct mode
    parser_reconstruct = subparsers.add_parser("reconstruct", 
        help="Reconstruct data by brute-forcing a specific prefix length."
    )
    parser_reconstruct.add_argument("compressed_file_input", help="Path to the .crch file to use.")
    parser_reconstruct.add_argument("reconstructed_file_output", help="Path to save the reconstructed data file.")
    parser_reconstruct.add_argument(
        "--prefix-len", type=int, required=True,
        help="The exact length of the unknown prefix to brute-force (e.g., 1, 2, 3)."
    )

    args = parser.parse_args()

    if args.mode == "prepare":
        prepare_compressed_file(args.original_file, args.compressed_file_output)
    elif args.mode == "auto-reconstruct":
        reconstruct_by_auto_increment(
            args.compressed_file_input, 
            args.reconstructed_file_output,
            args.start_prefix,
            args.max_prefix,
            args.max_time
        )
    elif args.mode == "reconstruct":
        reconstruct_by_bruteforce(args.compressed_file_input, args.reconstructed_file_output, args.prefix_len)

if __name__ == "__main__":
    main()