REPO_URL := https://github.com/sysown/proxysql.git
COMMIT_ID := 2637d28f365b1e765875dabfb2a0af4c96a906e5
WORKDIR := proxysql
BENCHMARKDIR := benchmark/proxysql
PATCH := libproxysql1.patch

.PHONY: all clean build

all:
	if [ ! -d "$(BENCHMARKDIR)/.git" ]; then \
		git clone $(REPO_URL) $(BENCHMARKDIR) && \
		cd $(WORKDIR) && git checkout $(COMMIT_ID); \
	fi

	cd $(BENCHMARKDIR) && make -j


	if [ ! -d "$(WORKDIR)/.git" ]; then \
		git clone $(REPO_URL) $(WORKDIR) && \
		cd $(WORKDIR) && git checkout $(COMMIT_ID) && \
		git apply ../$(PATCH); \
	fi

	cd $(WORKDIR) && make -j
clean:
	rm -rf $(WORKDIR)