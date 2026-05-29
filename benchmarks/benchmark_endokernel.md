# Comparison to Endokernel

To compare Secpoline with Endokernel, follow the following steps.


## Build Cerberus from source

Follow the instructions on the [Endokernel github](https://github.com/endokernel/test). 
This will setup the docker image containing the Endokernel prototype and all of its testcases.

## Build Secpoline in the Endokernel docker

Now clone and build Secpoline in the Endokernel docker.

## Update the Endokernel Testcases by Adding Secpoline

In the testcases directory:
    //add secpoline to the test setups

    iv_nocet_paths.append("baseline")

    iv_nocet_paths.append("secpoline")

    //Update get_row() by adding the secpoline case

    if path == "baseline" :

        r.append("baseline") if baseline else None

    elif path == "secpoline

        r.append("secpoline")

Then in the individual tests add secpoline as such:

zip.py

    if variable.iv_nocet_paths[j] == 'baseline':

        cmd = "time LD_LIBRARY_PATH=../libs/nocet ../bin/nocet/zip /tmp/test.zip -r ../linux-5.9.8 1> /dev/null"

        print ("Zip: baseline " + str(i) + " ...")
    
    elif variable.iv_nocet_paths[j] == 'secpoline':

        cmd = "time /path/to/secpoline/output/libloader.so /path/to/secpoline/output/secpoline ../bin/nocet/zip /tmp/test.zip -r ../linux-5.9.8 1> /dev/null"
        
        print ("Zip: secpoline " + str(i) + " ...")


sqlite.py

    if variable.iv_nocet_paths[i] == "baseline":
        filesuffix = "sqlite_baseline"
        cmd = "LD_LIBRARY_PATH=../libs/nocet ../bin/nocet/sqlite_speedtest"
        ctest = "baseline"
    elif variable.iv_nocet_paths[i] == "secpoline":
        filesuffix = "sqlite_secpoline"
        cmd = "/path/to/secpoline/output/libloader.so /path/to/secpoline/output/secpoline ../bin/nocet/sqlite_speedtest"
        ctest = "secpoline"

 
curl.py

    if path == "baseline":
        fp.write(b"baseline")
        row.append("baseline")
    elif path == "secpoline":
        fp.write(b"secpoline")
        row.append("secpoline")

    if variable.iv_nocet_paths[j] == 'baseline':
        cmd = "time LD_LIBRARY_PATH=../libs/nocet/ " + curlcmd
        print ("Beseline " + str(i) + " ...")
    elif variable.iv_nocet_paths[j] == 'secpoline':
        cmd = "time /path/to/secpoline/output/libloader.so /path/to/secpoline/output/secpoline " + curlcmd
        print ("secpoline " + str(i) + " ...")


lmbench.py

    if variable.iv_nocet_paths[i] == "baseline":
        filesuffix = "lmbench_baseline"
        cmdprefix = 'LD_LIBRARY_PATH=../libs/nocet ../bin/nocet/'
        tname = 'baseline '
    elif variable.iv_nocet_paths[i] == "secpoline":
        filesuffix = "lmbench_secpoline"
        cmdprefix = '/path/to/secpoline/output/libloader.so /path/to/secpoline/output/secpoline ../bin/nocet/'
        tname = 'secpoline '
    