#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <sys/types.h>
#include <errno.h>

#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/sockios.h>

#include <sys/un.h>
#include <android/log.h>
#include "../../../external/pppoe/jni/src/pppoe_status.h"


#define LOCAL_TAG "PPPOE_STATUS"
//#define PRINTF printf
#define PRINTF 



static pid_t read_pid(const char *pidfile)
{
	FILE *fp;
	pid_t pid;

	if ((fp = fopen(pidfile, "r")) == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, LOCAL_TAG,
            "failed to open %s (%s)\n", pidfile, strerror(errno));
		errno = ENOENT;
		return 0;
	}

	if (fscanf(fp, "%d", &pid) != 1) {
        __android_log_print(ANDROID_LOG_ERROR, LOCAL_TAG,
            "failed to read pid, make pid as 0\n");
		pid = 0;
	}
	fclose(fp);

    __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,
        "read_pid: %d\n", pid);
    
	return pid;
}


int pppoe_disconnect(void)
{
	pid_t pid;
    int ret;
    
    pid = read_pid(PPPOE_PIDFILE);
    if ( 0 == pid ) {
        __android_log_print(ANDROID_LOG_ERROR, LOCAL_TAG,
            "failed to stop ppp for no pid got\n" );
        return -1;
    }

    ret = kill(pid, 0);
    if ( 0 != ret ) {
        __android_log_print(ANDROID_LOG_ERROR, LOCAL_TAG,
            "process(#%d) died already???\n", pid );
        return -1;
    }

    /*
    The signals SIGKILL and SIGSTOP cannot 
    be caught, blocked, or ignored.
    So send SIGUSR1 to notify pppoe to send PADT.
    */
    ret = kill(pid, SIGUSR1);
    __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,
        "Send SIGUSR1 to pid(#%d), ret = %d\n", pid, ret );

    /*
    If no sleep before send SIGKILL, pppoe will just being killed
    rather than sending PADT.
    */
    __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,
        "sleep before send SIGKILL to pid(#%d)\n", pid );
    
    sleep(5);

    ret = kill(pid, SIGKILL);
    __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,
        "Send SIGKILL to pid(#%d), ret = %d\n", pid, ret );

	unlink(PPPOE_PIDFILE);
    __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,
        "removed %s\n", PPPOE_PIDFILE );

    return 0;    
}



