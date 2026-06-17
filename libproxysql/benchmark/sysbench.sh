#!/bin/bash
BASEDIR="$(realpath "$(dirname "$SCRIPT")")"
REAL_PROXY_PATH="$(realpath "$BASEDIR/proxysql")"
LIBPROXY_PATH="$(realpath "$BASEDIR/../proxysql")"
SECPOLINE_PATH="$(realpath "$BASEDIR/../../")"
PROXY_PORT="6033"
SERVER_PORT="3306"
TIME="300"
#Currently only works for 1 thread
THREADS="1"
ITER="1 2 3 4 5"

TABLE_EXISTS=$(mysql -h 127.0.0.1 -u appuser -p apppass testdb -s N -e "SHOW TABLES LIKE 'sbtest1';")

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


pkill -9 "proxysql"
$REAL_PROXY_PATH/src/proxysql -c $LIBPROXY_PATH/etc/proxysql.cnf -f 2>/dev/null&
PROXY_PID=$!
sleep 5
for i in $ITER; do
    echo non-secpoline_$i
    CMD="sysbench oltp_read_write --mysql-host=127.0.0.1 --mysql-port=$PROXY_PORT --mysql-user=appuser --mysql-password=apppass --mysql-db=testdb --tables=8 --table-size=10000000 --threads=$THREADS --time=$TIME run"
    #echo "$CMD"
    run_sysbench "$CMD"
done
pkill -9 "proxysql"

for i in $ITER; do
    echo no proxy_$i
    CMD="sysbench oltp_read_write --mysql-host=127.0.0.1 --mysql-port=$SERVER_PORT --mysql-user=appuser --mysql-password=apppass --mysql-db=testdb --tables=8 --table-size=10000000 --threads=$THREADS --time=$TIME run"
    #echo "$CMD"
    run_sysbench "$CMD"
done

for i in $ITER; do
    echo secpoline_$i
    CMD="env PROXYSQL_CONFIG=$LIBPROXY_PATH/etc/proxysql.cnf $SECPOLINE_PATH/output/libloader.so $SECPOLINE_PATH/output/secpoline /usr/bin/sysbench oltp_read_write --mysql-host=127.0.0.1 --mysql-port=$PROXY_PORT --mysql-user=appuser --mysql-password=apppass --mysql-db=testdb --tables=8 --table-size=10000000 --threads=$THREADS --time=$TIME run"
    echo "$CMD"
    run_sysbench "$CMD"
    pkill -f libloader.so 2>/dev/null
done




