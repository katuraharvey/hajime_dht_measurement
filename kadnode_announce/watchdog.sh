count=0
until sh run_kadnode_announce.sh; do
    #mv kad.log kad.log$count
    count=$((count+1))
    echo "Server kadnode announce crashed with exit code $?.  Respawning.." >&2
    sleep 1
done
