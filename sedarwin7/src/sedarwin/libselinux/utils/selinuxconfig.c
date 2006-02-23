#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <selinux/selinux.h>
#include <selinux/get_default_type.h>

int main(int argc __attribute__ ((unused)), char **argv) 
{
        int enforce;
	if (selinux_getenforcemode(&enforce)==0) {
	  switch (enforce) {
	  case 1:
	    printf("selinux state=\"enforcing\"\n");
	    break;
	  case 0:
	    printf("selinux state=\"permissive\"\n");
	    break;
	  case -1:
	    printf("selinux state=\"disabled\"\n");
	    break;
	  }
	}

	printf("policypath=\"%s\"\n", selinux_policy_root());
	printf("default_type_path=\"%s\"\n", selinux_default_type_path());
	printf("default_context_path=\"%s\"\n", selinux_default_context_path());
	printf("default_failsafe_context_path=\"%s\"\n", selinux_failsafe_context_path());
	printf("binary_policy_path=\"%s\"\n", selinux_binary_policy_path());
	printf("user_contexts_path=\"%s\"\n", selinux_user_contexts_path());
	printf("contexts_path=\"%s\"\n", selinux_contexts_path());
	exit(0);

}
