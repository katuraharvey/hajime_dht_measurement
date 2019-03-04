count=0
until sh run_kadnode.sh; do
    #mv kad.log kad.log$count
    count=$((count+1))
    echo "Server kadnode lookup crashed with exit code $?.  Respawning.." >&2
    sleep 1
done
