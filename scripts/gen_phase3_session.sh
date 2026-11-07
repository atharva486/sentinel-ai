#!/bin/bash
# Generate one Phase 3 session's traffic.
# Usage: gen_phase3_session.sh <session_name> <benign_mix> <attack_mix> <duration>
#   e.g. gen_phase3_session.sh runH "normal:200,slow_mobile:50,large_upload:30,api_crawler:40,keepalive_polling:30,browser_parallel:50" "slowloris:50,ruddy:25,flood:25,low_and_slow:25" 120
set -euo pipefail

SESSION="$1"
BENIGN_MIX="$2"
ATTACK_MIX="$3"
DURATION="${4:-120}"

REPO="/home/atharva/l7-dos-defender"
RUN_DIR="$REPO/reports/runs/$SESSION"
PCAP="$REPO/captures/$SESSION.pcap"
SIDE_LOG="$RUN_DIR/side_log.jsonl"

mkdir -p "$RUN_DIR"
rm -f "$SIDE_LOG"
rm -f "$PCAP"

echo "=== Generating session $SESSION ==="
echo "  Benign mix: $BENIGN_MIX"
echo "  Attack mix: $ATTACK_MIX"
echo "  Duration: ${DURATION}s"
echo "  Pcap: $PCAP"
echo "  Side log: $SIDE_LOG"

# Start tcpdump on proxy container
echo "Starting tcpdump on proxy..."
docker compose exec -d proxy tcpdump -i eth0 -s 0 -w "/captures/$SESSION.pcap" tcp port 80
sleep 1

# Run generators inside Docker containers
# We distribute benign across legit-loadgen, attacks across slow-gen and flood-gen
echo "Starting traffic generation..."

# Parse benign mix and distribute across containers
# For simplicity: run all benign from legit-loadgen, all attacks from slow-gen + flood-gen
# benign_worker handles all sub_types; slowloris/ruddy from slow-gen; flood/low_and_slow from flood-gen

# Extract benign sub-types
BENIGN_NORMAL=$(echo "$BENIGN_MIX" | grep -oP 'normal:\K\d+' || echo 0)
BENIGN_SLOW=$(echo "$BENIGN_MIX" | grep -oP 'slow_mobile:\K\d+' || echo 0)
BENIGN_LARGE=$(echo "$BENIGN_MIX" | grep -oP 'large_upload:\K\d+' || echo 0)
BENIGN_API=$(echo "$BENIGN_MIX" | grep -oP 'api_crawler:\K\d+' || echo 0)
BENIGN_KA=$(echo "$BENIGN_MIX" | grep -oP 'keepalive_polling:\K\d+' || echo 0)
BENIGN_BROWSER=$(echo "$BENIGN_MIX" | grep -oP 'browser_parallel:\K\d+' || echo 0)

# Extract attack types
ATTACK_SLOWLORIS=$(echo "$ATTACK_MIX" | grep -oP 'slowloris:\K\d+' || echo 0)
ATTACK_RUDY=$(echo "$ATTACK_MIX" | grep -oP 'ruddy:\K\d+' || echo 0)
ATTACK_FLOOD=$(echo "$ATTACK_MIX" | grep -oP 'flood:\K\d+' || echo 0)
ATTACK_LOWANDSSLOW=$(echo "$ATTACK_MIX" | grep -oP 'low_and_slow:\K\d+' || echo 0)

TOTAL_BENIGN=$((BENIGN_NORMAL + BENIGN_SLOW + BENIGN_LARGE + BENIGN_API + BENIGN_KA + BENIGN_BROWSER))
TOTAL_ATTACK=$((ATTACK_SLOWLORIS + ATTACK_RUDY + ATTACK_FLOOD + ATTACK_LOWANDSSLOW))

echo "  Total benign: $TOTAL_BENIGN, Total attack: $TOTAL_ATTACK"

# Run benign workers from legit-loadgen container
if [ "$TOTAL_BENIGN" -gt 0 ]; then
    echo "  Running $TOTAL_BENIGN benign connections from legit-loadgen..."
    docker compose exec -T legit-loadgen python generate.py --mode mix --duration $((DURATION + 30)) --label "$SESSION" \
        --benign-mix "$BENIGN_MIX" --side-log "/reports/runs/$SESSION/side_log.jsonl" \
        --dur-min 30 --dur-max 180
fi

# Run slowloris + ruddy from slow-gen container
SLOW_ATTACK=$((ATTACK_SLOWLORIS + ATTACK_RUDY))
if [ "$SLOW_ATTACK" -gt 0 ]; then
    echo "  Running $SLOW_ATTACK slow attacks from slow-gen..."
    docker compose exec -T slow-gen python generate.py --mode mix --duration $((DURATION + 30)) --label "$SESSION" \
        --attack-mix "slowloris:$ATTACK_SLOWLORIS,ruddy:$ATTACK_RUDY" --side-log "/reports/runs/$SESSION/side_log.jsonl" \
        --dur-min 30 --dur-max 180
fi

# Run flood + low_and_slow from flood-gen container
FLOOD_ATTACK=$((ATTACK_FLOOD + ATTACK_LOWANDSSLOW))
if [ "$FLOOD_ATTACK" -gt 0 ]; then
    echo "  Running $FLOOD_ATTACK fast attacks from flood-gen..."
    docker compose exec -T flood-gen python generate.py --mode mix --duration $((DURATION + 30)) --label "$SESSION" \
        --attack-mix "flood:$ATTACK_FLOOD,low_and_slow:$ATTACK_LOWANDSSLOW" --side-log "/reports/runs/$SESSION/side_log.jsonl" \
        --dur-min 30 --dur-max 180
fi

echo "  Traffic generation complete, waiting for side log to flush..."
sleep 5

# Stop tcpdump
echo "Stopping tcpdump..."
docker compose exec -T proxy pkill -f "tcpdump.*$SESSION.pcap" || true
sleep 2

# Copy pcap from proxy container to host
echo "Copying pcap from proxy..."
docker compose exec -T proxy cat "/captures/$SESSION.pcap" > "$PCAP" 2>/dev/null || true

# Verify
if [ -f "$PCAP" ]; then
    PCAP_SIZE=$(wc -c < "$PCAP")
    echo "  Pcap saved: $PCAP ($PCAP_SIZE bytes)"
else
    echo "  WARNING: Pcap not found at $PCAP"
fi

if [ -f "$SIDE_LOG" ]; then
    SIDE_ROWS=$(wc -l < "$SIDE_LOG")
    echo "  Side log saved: $SIDE_LOG ($SIDE_ROWS rows)"
else
    echo "  WARNING: Side log not found at $SIDE_LOG"
fi

echo "=== Session $SESSION complete ==="
