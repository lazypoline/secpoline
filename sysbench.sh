SECPOLINE_PATH="$1"
PROXY_PATH="$2"
LIBPROXY_PATH="$3"
if [ "$#" -ne 3 ]; then
echo "Usage: $0 <SECPOLINE_PATH> <PROXY_PATH>  <LIBPROXY_PATH> "
exit 1
fi
PORT="6033"
BASE_PORT="3306"
TIME="300"
THREADS="1"
ITER="1 2 3 4 5"

TABLE_EXISTS=$(mysql -h127.0.0.1 -uappuser -papppass testdb -sN -e "SHOW TABLES LIKE 'sbtest1';")



run_sysbench() {
retries=0

while :; do
    OUTPUT=$(eval "$1" 2>&1 | tr -d '\000')

    echo "$OUTPUT" | grep -q 'SQL statistics'
    if [ "$?" -eq 0 ]; then
        break
    fi

    echo $OUTPUT
    echo "retrying: SQL statistics not found"
    retries=$((retries+1))
done

echo "retries: $retries"

echo "$OUTPUT" | awk '
/^[[:space:]]+transactions:/ ||
/^[[:space:]]+queries:/ ||
/^Latency \(ms\):/ ||
/^[[:space:]]+min:/ ||
/^[[:space:]]+avg:/ ||
/^[[:space:]]+max:/ ||
/^[[:space:]]+95th percentile:/ ||
/^[[:space:]]+sum:/ ||
/^Threads fairness:/ ||
/^[[:space:]]+events \(avg\/stddev\):/ ||
/^[[:space:]]+execution time \(avg\/stddev\):/
'

}


if [ -z "$TABLE_EXISTS" ]; then
sysbench oltp_read_write --mysql-host=127.0.0.1 --mysql-user=appuser --mysql-password=apppass --mysql-db=testdb --tables=8 --table-size=10000000 prepare
fi
for i in $ITER; do
    echo secpoline_$i
    CMD="$SECPOLINE_PATH/build/libloader.so $SECPOLINE_PATH/build/secpoline /usr/bin/sysbench oltp_read_write --mysql-host=127.0.0.1 --mysql-port=$PORT --mysql-user=appuser --mysql-password=apppass --mysql-db=testdb --tables=8 --table-size=10000000 --threads=$THREADS --time=$TIME run"
    #echo "$CMD"
    run_sysbench "$CMD"
    pkill -f libloader.so 2>/dev/null
done

for i in $ITER; do
    echo no proxy_$i
    CMD="sysbench oltp_read_write --mysql-host=127.0.0.1 --mysql-port=$BASE_PORT --mysql-user=appuser --mysql-password=apppass --mysql-db=testdb --tables=8 --table-size=10000000 --threads=$THREADS --time=$TIME run"
    #echo "$CMD"
    run_sysbench "$CMD"
done

$PROXY_PATH/src/proxysql -c $LIBPROXY_PATH/etc/proxysql.cnf &
PROXY_PID=$!
sleep 1
for i in $ITER; do
    echo non-secpoline_$i
    CMD="sysbench oltp_read_write --mysql-host=127.0.0.1 --mysql-port=$PORT --mysql-user=appuser --mysql-password=apppass --mysql-db=testdb --tables=8 --table-size=10000000 --threads=$THREADS --time=$TIME run"
    #echo "$CMD"
    run_sysbench "$CMD"
done
kill -9 PROXY_PID


