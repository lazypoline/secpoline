#!/usr/bin/env bash
set -euo pipefail

cleanup() {
    echo "[*] Cleaning up: removing falco module (if loaded)"
    sudo rmmod falco 2>/dev/null || true
}

# Note: Removed the EXIT trap from here so it doesn't collide with the TMP_DIR cleanup
trap cleanup INT TERM

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECPOLINE_DIR="$(realpath "$SCRIPT_DIR/../../output")"


KERNEL_URL="https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/linux-6.12.1.tar.gz"
ARCHIVE_NAME="linux-6.12.1.tar.gz"

TMP_DIR="$(mktemp -d)"
# This trap will now handle cleaning up the directory on script exit
trap 'rm -rf "$TMP_DIR"; cleanup' EXIT

cd "$TMP_DIR"

echo "[*] Downloading kernel..."
wget -q "$KERNEL_URL" -O "$ARCHIVE_NAME"

echo "[*] Extracting kernel..."
tar -xzf "$ARCHIVE_NAME"

# -------------------------
# Falco path relative to script
# -------------------------
FALCO_DIR="$(realpath "$SCRIPT_DIR/../../falco")"
BUILD_DIR="$FALCO_DIR/build"

if [[ ! -d "$BUILD_DIR" ]]; then
    mkdir -p "$BUILD_DIR"
fi

cd "$BUILD_DIR"

cmake -DUSE_BUNDLED_DEPS=ON ..

make falco -j$(nproc)
make driver -j$(nproc)

FALCO_BIN="$FALCO_DIR/build/userspace/falco/falco"
DRIVER_BIN="$FALCO_DIR/build/driver/falco.ko"

if [[ ! -f "$DRIVER_BIN" ]]; then
    echo "[!] Falco kernel module not found!"
    exit 1
fi

if [[ ! -f "$FALCO_BIN" ]]; then
    echo "[!] Falco binary not found!"
    exit 1
fi

# ---------------------------------------------------------
# BENCHMARK LOOP (Run 10 times)
# ---------------------------------------------------------
ITERATIONS=10

BASE_TIME=0
FALCO_TIME=0
SECPOLINE_TIME=0

echo "[*] Starting base loop ($ITERATIONS iterations)..."

for i in $(seq 1 $ITERATIONS); do
    echo "--- Run $i ---"
    
    # Ensure a clean slate for the zip target file
    rm -f "$TMP_DIR/linux.zip"
    
    # Capture only the real elapsed time using /usr/bin/time
    # -f "%e" outputs just the seconds (e.g., 1.45)
    RUN_TIME=$( /usr/bin/time -f "%e" zip -q -r "$TMP_DIR/linux.zip" "$TMP_DIR/linux-6.12.1" 2>&1 )
    
    echo "[+] Run $i took: ${RUN_TIME}s"
    
    # Add to cumulative total using bc for floating-point math
    BASE_TIME=$(echo "$BASE_TIME + $RUN_TIME" | bc)
done


echo "[*] Starting falco kmod loop ($ITERATIONS iterations)..."

sudo insmod "$DRIVER_BIN"

sudo "$FALCO_BIN" \
    -c "$FALCO_DIR/falco_base.yaml" \
    -r "$FALCO_DIR/rules/falco_rules.yaml" >/dev/null 2>&1 &
FALCO_PID=$!
    sleep 1 

for i in $(seq 1 $ITERATIONS); do
    echo "--- Run $i ---"
    
    # Ensure a clean slate for the zip target file
    rm -f "$TMP_DIR/linux.zip"
    
    # Capture only the real elapsed time using /usr/bin/time
    # -f "%e" outputs just the seconds (e.g., 1.45)
    RUN_TIME=$( /usr/bin/time -f "%e" zip -q -r "$TMP_DIR/linux.zip" "$TMP_DIR/linux-6.12.1" 2>&1 )
    
    echo "[+] Run $i took: ${RUN_TIME}s"
    
    # Add to cumulative total using bc for floating-point math
    FALCO_TIME=$(echo "$FALCO_TIME + $RUN_TIME" | bc)
done

    echo "[*] Stopping falco..."
    sudo kill "$FALCO_PID" 2>/dev/null || true
    wait "$FALCO_PID" 2>/dev/null || true
    sudo rmmod falco 2>/dev/null || true



echo "[*] Starting Secpoline loop ($ITERATIONS iterations)..."

for i in $(seq 1 0); do
    echo "--- Run $i ---"
    
    # Ensure a clean slate for the zip target file
    rm -f "$TMP_DIR/linux.zip"
    
    # 1. Create a tiny temp file just for this run's time
    TIME_TMP=$(mktemp)

    # 2. Run the command. 
    # We direct all regular output to /dev/null. 
    # The "-o" flag forces the time utility to write the number straight to our file.
    env FALCO_DIR="$FALCO_DIR" /usr/bin/time -f "%e" -o "$TIME_TMP" "$SECPOLINE_DIR/libloader.so" "$SECPOLINE_DIR/secpoline" /usr/bin/zip -q -r "$TMP_DIR/linux.zip" "$TMP_DIR/linux-6.12.1" > /dev/null 2>&1

    # 3. Read the number from the file into your variable
    RUN_TIME=$(cat "$TIME_TMP")

    # 4. Clean up the tiny temp file
    rm -f "$TIME_TMP"

    # 5. Handle the math safely (strip any accidental whitespaces)
    RUN_TIME=$(echo "$RUN_TIME" | tr -d '[:space:]')

    echo "[+] Run $i took: ${RUN_TIME}s"

    SECPOLINE_TIME=$(echo "$SECPOLINE_TIME + $RUN_TIME" | bc)
done

# ---------------------------------------------------------
# CALCULATE AVERAGE
# ---------------------------------------------------------
BASE_TIME=$(echo "scale=3; $BASE_TIME / $ITERATIONS" | bc)
FALCO_TIME=$(echo "scale=3; $FALCO_TIME / $ITERATIONS" | bc)
SECPOLINE_TIME=$(echo "scale=3; $SECPOLINE_TIME / $ITERATIONS" | bc)

echo "========================================"
echo "Benchmark Complete"
echo "Average Time:"
echo "BASELINE: ${BASE_TIME}"
echo "KMOD: ${FALCO_TIME}"
echo "SECPOLINE: ${SECPOLINE_TIME}"
echo "========================================"