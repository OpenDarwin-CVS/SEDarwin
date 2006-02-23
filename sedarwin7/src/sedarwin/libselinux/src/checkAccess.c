#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <selinux/selinux.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

int checkPasswdAccess(access_vector_t requested) {
        int status=-1;
        security_context_t user_context;
        if (is_selinux_enabled() == 0) 
                return 0;
        if( getprevcon(&user_context)==0 ) {
                struct av_decision avd;
                int retval = security_compute_av(user_context,
                                                 user_context,
                                                 SECCLASS_PASSWD,
                                                 requested,
                                                 &avd);
                
                if ((retval == 0) && 
                    ((requested & avd.allowed) == requested)) {
                        status=0;
                }
                freecon(user_context);
        }
        
        if (status != 0 && security_getenforce()==0) 
                status=0;
        
        return status;
}
