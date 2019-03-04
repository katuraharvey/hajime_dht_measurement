#!/bin/sh
CAPTURE_DIR="/home/ubuntu/hajime_dht/captures/"
DATA_DIR="/home/ubuntu/hajime_dht/data/announce"

last_created=""
inotifywait -m -e create --format '%w%f' "$CAPTURE_DIR" | while read f

do
    echo $f
    if [ ! -z "$last_created" ]; then
        echo $last_created
        python pcap_to_log_tuples.py -f "$last_created" "$DATA_DIR"
    fi
    last_created="$f"
    echo $last_created
done
