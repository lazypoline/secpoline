# Comparison to Cerberus

To compare Secpoline with Cerberus, follow the following steps.


## Build Cerberus from source

Follow the instructions on the [ Cerberus github](https://github.com/ku-leuven-msec/The-Cerberus-Project). 
Next you will need a custom kenel patch to run Cerberus. We have ported this patch to the Linux kernel version 6.12.0. It is called `linux-6.12.0-full-cerberus.patch`.

## Run lighttpd

To run lighttpd, we used the version provided with Cerberus. Follow the instructions there to build.
Our run commands:

Native:

    LD_LIBRARY_PATH="/path-to/The-Cerberus-Project/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" sudo taskset -c 0-3 /path-to/The-Cerberus-Project/cerberus_ReMon/benchmarks/lighttpd-native/sbin/lighttpd -D -f /path-to/The-Cerberus-Project/cerberus_ReMon/benchmarks/conf/lighttpd.conf.5
  
 Cerberus:
 

    sudo taskset -c 0 ./MVEE -N 1 -- "LD_LIBRARY_PATH="/path-to/The-Cerberus-Project/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" /path-to/The-Cerberus-Project/cerberus_ReMon/benchmarks/lighttpd-native/sbin/lighttpd -D -f /path-to/The-Cerberus-Project/cerberus_ReMon/benchmarks/conf/lighttpd.conf.1"


Secpoline:

    LD_LIBRARY_PATH="/path-to/The-Cerberus-Project/cerberus_ReMon/benchmarks/openssl/native-shared/.openssl/lib/:/usr/local/lib" sudo taskset -c 0-1 /path-to/secpoline/output/libloader.so /path-to/secpoline/output/secpoline /path-to/The-Cerberus-Project/cerberus_ReMon/benchmarks/lighttpd-native/sbin/lighttpd -D -f /path-to/The-Cerberus-Project/cerberus_ReMon/benchmarks/conf/lighttpd.conf.3

With the conf.1 for 1 worker, conf.3 for 2 workers and conf.5 for 4 workers (thank you for that, Cerberus).

We used wrk to measure the performance.

    sudo taskset -c 8-11 wrk/wrk -t8 -c64 -d10s --timeout 10s http://127.0.0.1:3000/index.html
    sudo taskset -c 6-11 wrk/wrk -t6 -c24 -d10s --timeout 10s http://127.0.0.1:3000/index.html  # 4 workers

##  Run Apache

Get the apache source. Build it. Depending on the configuration, we used different wrk commands. Also pin to a correct amount of cores.

Native:

    sudo taskset -c 0-3 /path-to/apache/httpd-binary/bin/httpd -f /path-to/apache/httpd-binary/conf/httpd.conf 

Cerberus (from the MVEE executable):

    sudo taskset -c 0-3 ./MVEE -N 1 -- "/hpath-to/apache/httpd-binary/bin/httpd -f /home/anton/apache/httpd-binary/conf/httpd.conf"

Secpoline:

    sudo taskset -c 0-3 /path-to/secpoline/output/libloader.so /path-to/secpoline/output/secpoline /path-to/apache/httpd-binary/bin/httpd -f /path-to/apache/httpd-binary/conf/httpd.conf 

wrk:

    sudo taskset -c 2-11 wrk/wrk -t14 -c28 -d10s --timeout 10s http://127.0.0.1:3000/index.html # apache 1 worker
    sudo taskset -c 6-11 wrk/wrk -t6 -c24 -d10s --timeout 10s http://127.0.0.1:3000/index.html # apache 4 workers
    sudo  taskset  -c  8-11  wrk/wrk  -t8  -c64  -d10s  --timeout 10s  http://127.0.0.1:3000/index.html   # apache 64 workers

For the config, change the file in apache at: `/apache/httpd-binary/conf/extra/http-mpm.conf`.

    # 1. For Prefork (Single Process)
    <IfModule mpm_prefork_module>
        StartServers             1
        MinSpareServers          1
        MaxSpareServers          1
        MaxRequestWorkers        1
        MaxConnectionsPerChild   0
    </IfModule>
    
    # 1 worker 1 thread
    
    <IfModule mpm_event_module>
        StartServers             1
        ServerLimit              1
        MinSpareThreads          1
        MaxSpareThreads          1
        ThreadsPerChild          1
        MaxRequestWorkers        1
        MaxConnectionsPerChild   0
    </IfModule>
    
    <IfModule mpm_worker_module>
        StartServers             1
        ServerLimit              1
        MinSpareThreads          1
        MaxSpareThreads          1
        ThreadsPerChild          1
        MaxRequestWorkers        1
        MaxConnectionsPerChild   0
    </IfModule>
    
    # 4 workers
    <IfModule mpm_event_module>
        ServerLimit              4
        StartServers             4
    
        ThreadsPerChild          8
        MinSpareThreads          16
        MaxSpareThreads          32
    
        MaxRequestWorkers        32
        
        MaxConnectionsPerChild   0
        AsyncRequestWorkerFactor 4
    </IfModule>
    
    # 64 workers
    <IfModule mpm_event_module>
        ServerLimit              8
        StartServers             8
    
        ThreadsPerChild          8
    
        MinSpareThreads          16
        MaxSpareThreads          32
    
        MaxRequestWorkers        64
    
        MaxConnectionsPerChild   0
        AsyncRequestWorkerFactor 4
    </IfModule>