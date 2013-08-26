export  PATH=/usr/local/bin:${PATH}
export LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}

gcc -lpthread -lnl-3 -I/usr/local/include/libnl3 iwarp_pm_server.c iwarp_pm_common.c iwarp_pm_helper.c -o iwarp_pm_ten_daemon
chkconfig --add ./scriptabove
