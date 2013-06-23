#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <netdb.h>
#include <utmp.h>
#include <pwd.h>
#include <setjmp.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cutils/properties.h>
#include <sys/un.h>

#include <android/log.h>

#include <netwrapper.h>

#define LOCAL_TAG "NETWRAPPER"


static char request_buf[REQUEST_BUF_LEN];


struct request_handler_map
{
    char request[REQUEST_BUF_LEN];
    pf_request_handler handler;
    struct request_handler_map *next;
};


static struct request_handler_map *map_list = NULL;

#define ACK_BUF_LEN 128
#define RESEND_CNT_MAX 10

static char request_buf[REQUEST_BUF_LEN];
static char ack_buf[ACK_BUF_LEN];
static int  req_no = 0;

struct netwrapper_ctrl * netwrapper_ctrl_open
(const char *client_path, const char *server_path)
{
	struct netwrapper_ctrl *ctrl;
	int ret;
	size_t res;
	int tries = 0;

    __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,"%s(server_path = %s)\n", __FUNCTION__, server_path);
	ctrl = malloc(sizeof(*ctrl));
	if (ctrl == NULL)
		return NULL;
	memset(ctrl, 0, sizeof(*ctrl));

	ctrl->s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (ctrl->s < 0) {
		free(ctrl);
		return NULL;
	}
    __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,"%s(ctrl->s = %d)\n", __FUNCTION__, ctrl->s);

	ctrl->local.sun_family = AF_UNIX;

try_again:
	ret = snprintf(ctrl->local.sun_path, sizeof(ctrl->local.sun_path),
			  "%s-%d", client_path, getpid());

    __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,"%s: ctrl->local.sun_path: %s\n", __FUNCTION__, ctrl->local.sun_path);
	if (ret < 0 || (size_t) ret >= sizeof(ctrl->local.sun_path)) {
		close(ctrl->s);
		free(ctrl);
		return NULL;
	}
	tries++;
	if (bind(ctrl->s, (struct sockaddr *) &ctrl->local,
		    sizeof(ctrl->local)) < 0) {
#if 1		    
		if (errno == EADDRINUSE && tries < 2) {
			/*
			 * getpid() returns unique identifier for this instance
			 * of netwrapper_ctrl, so the existing socket file must have
			 * been left by unclean termination of an earlier run.
			 * Remove the file and try again.
			 */
			unlink(ctrl->local.sun_path);
            		__android_log_print(ANDROID_LOG_ERROR, LOCAL_TAG,"%s: bind failed(%s)\n", __FUNCTION__, strerror(errno));
			goto try_again;
		}
        
        __android_log_print(ANDROID_LOG_ERROR, LOCAL_TAG,"%s: bind failed(%s)\n", __FUNCTION__, strerror(errno));
		close(ctrl->s);
		free(ctrl);
		return NULL;
#endif
    }

	ctrl->dest.sun_family = AF_UNIX;
	res = strlcpy(ctrl->dest.sun_path, server_path,
			 sizeof(ctrl->dest.sun_path));
	if (res >= sizeof(ctrl->dest.sun_path)) {
		close(ctrl->s);
		free(ctrl);
		return NULL;
	}

    __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,"%s: ctrl->dest.sun_path: %s\n", __FUNCTION__, ctrl->dest.sun_path);
	if (connect(ctrl->s, (struct sockaddr *) &ctrl->dest,
		    sizeof(ctrl->dest)) < 0) {
		close(ctrl->s);
        __android_log_print(ANDROID_LOG_ERROR, LOCAL_TAG,"%s: connection failed\n", __FUNCTION__);
		unlink(ctrl->local.sun_path);
		free(ctrl);
		return NULL;
	}

    __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,"connection to netwrapper OK\n");
	return ctrl;
}


void netwrapper_ctrl_close(struct netwrapper_ctrl *ctrl)
{
	if (ctrl == NULL)
		return;
	unlink(ctrl->local.sun_path);
	if (ctrl->s >= 0)
		close(ctrl->s);
	free(ctrl);
}


int netwrapper_ctrl_request(struct netwrapper_ctrl *ctrl, const char *cmd, size_t cmd_len)
{   
    int nwritten = -1;
    int acked = 0;
    fd_set rfds;
    struct timeval tv;
    int res;
    int pid_and_reqno_len =0;
    int resend_cnt = 0;
    
    do {
        request_buf[0] = 0;
        nwritten = sprintf(request_buf, "%d\t", getpid());
        nwritten += sprintf(request_buf + nwritten, "%d\t", req_no++);
        pid_and_reqno_len = nwritten;
        nwritten += sprintf(request_buf + nwritten, "%s", cmd);

    	if (send(ctrl->s, request_buf, nwritten, 0) < 0) {
    		__android_log_print(ANDROID_LOG_ERROR, LOCAL_TAG,"send command[%s] failed(%s)\n", cmd, strerror(errno));
    		goto exit_func;
    	}

        resend_cnt++;

		tv.tv_sec = 10;
		tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(ctrl->s, &rfds);
		res = select(ctrl->s + 1, &rfds, NULL, NULL, &tv);
        if ( res < 0 ) {
        	__android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,"failed to select(%s)\n", strerror(errno));
            goto exit_func;
        } else if ( 0 == res ){
        	__android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,"Timeout to recv ack, resend request\n");        
            continue;            
        }else if (FD_ISSET(ctrl->s, &rfds)) {
			res = recv(ctrl->s, ack_buf, ACK_BUF_LEN-1, 0);
			if (res < 0) {
            	__android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,"failed to recv ack(%s)\n", strerror(errno));
                goto exit_func;
			}

            if (0 == strncmp(ack_buf, request_buf,pid_and_reqno_len)) {
            	__android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,"recved VALID ack\n");
                acked = 1;                
            }
            else {
            	__android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,"recved INVALID ack: pid_and_reqno_len(%d)\n", pid_and_reqno_len);
                ack_buf[pid_and_reqno_len] = 0;
                request_buf[pid_and_reqno_len] = 0;
            	__android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,"ack_buf[%s]\n", ack_buf);
            	__android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,"request_buf[%s]\n", request_buf);                
            }
		}
    }while(!acked && resend_cnt < RESEND_CNT_MAX);

exit_func:
	__android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,"send command[%s] %s\n", cmd, acked ? "OK" : "failed");
	return acked ? 0 : -1;
}


int netwrapper_register_handler(const char *request, pf_request_handler handler)
{
    struct request_handler_map *map = malloc(sizeof(struct request_handler_map));

    if (!map) {
        __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG, "malloc failed");
        return -1;
    }

    memset(map, '\0', sizeof(*map));
    map->handler = handler;
    strncpy(map->request, request,sizeof(map->request) - 1);

    if (!map_list) {
        map_list = map;
    }
    else {
        map->next = map_list;
        map_list = map;
    }

    return 0;
}



static pf_request_handler get_handler(const char *request)
{
    struct request_handler_map *map;

    for (map = map_list; map; map = map->next) {
        __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,
        "request[%s]\n",request);

        __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,
        "map->request[%s]\n",map->request);
        if ( 0 == strncmp(map->request, request, strlen(map->request)))
            return map->handler;
    }

    return (pf_request_handler)NULL;
}


static const char NETWRAPPER_SELECT_TO_PROP_NAME[]    = "net.wrapper.select.timeout";
int netwrapper_main(const char *server_path)
{
    int socket_fd;
    struct sockaddr_un cli_addr, serv_addr;
    int i, len, clilen = 0;

    socket_fd = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        __android_log_print(ANDROID_LOG_ERROR, LOCAL_TAG,
            "failed to create socket(%s)\n", strerror(errno));
        exit(-1);
    }

	memset(&serv_addr,0,sizeof(serv_addr));
    __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,
        "create AF_UNIX socket:%d OK\n",socket_fd);

	unlink(server_path);
	serv_addr.sun_family = AF_UNIX;
	strncpy(serv_addr.sun_path, server_path, sizeof(serv_addr.sun_path) - 1);

	if (bind(socket_fd, (struct sockaddr *)&serv_addr,  sizeof(struct sockaddr_un)) < 0) {
        __android_log_print(ANDROID_LOG_ERROR, LOCAL_TAG,
            "failed to bind socket(%s)\n", strerror(errno));
		exit(-1);
	}

	struct timeval tv;
	int res;
	fd_set rfds;
    char *cmd;
    
	for (;;) {
		char str_to[32] = {0,};     
		property_get(NETWRAPPER_SELECT_TO_PROP_NAME, str_to, "10");
		tv.tv_sec = atoi(str_to);
		tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(socket_fd, &rfds);
		res = select(socket_fd + 1, &rfds, NULL, NULL, &tv);
		if (res > 0 && FD_ISSET(socket_fd, &rfds)) {
            clilen = sizeof (struct sockaddr_un);
			res = recvfrom(socket_fd, request_buf, REQUEST_BUF_LEN-1, 0,
                            (struct sockaddr *)&cli_addr,&clilen);
			if (res < 0) {
                __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,
                    "FAILED TO RECVFROM\n");
               
				return res;
			}
            
            __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,
                "client: [%s][%d]\n",
                cli_addr.sun_path, clilen);
            
            request_buf[res] = '\0';

            cmd = strchr(request_buf, '\t');
            if (!cmd) {
                __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,
                    "recv invalid request(No TAB found): [%s]\n",request_buf);
                continue;
            }
            cmd++;
            
            cmd = strchr(cmd, '\t');
            if (!cmd) {
                __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,
                    "recv invalid request(Second TAB NOT found): [%s]\n",request_buf);
                continue;
            }
            cmd++;
            
        	if (sendto(socket_fd, request_buf, cmd - request_buf, 0,
                        (struct sockaddr *)&cli_addr, clilen) < 0) {
        		__android_log_print(ANDROID_LOG_ERROR, LOCAL_TAG,"failed to send ACK(%s)\n", strerror(errno));
        		continue;
        	}

            __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,
                "recv request: [%s]\n",cmd);
            
            pf_request_handler handler = get_handler(cmd);
            if ( handler ) {
                handler(cmd);
            }
            else {
                __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG,
                    "no handler found for request\n");
            }
		}
	}

    __android_log_print(ANDROID_LOG_INFO, LOCAL_TAG, "EXIT\n");
    close(socket_fd);
    return 0;
}

