./run_occlum_redis.sh &
sleep 60
echo 'start client'
/usr/local/occlum/x86_64-linux-musl/redis/bin/redis-benchmark -n 1000
