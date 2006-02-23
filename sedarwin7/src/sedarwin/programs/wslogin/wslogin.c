
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/mac.h>

#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <stdio.h>

#include <selinux/get_context_list.h> 

#define errexit(args...)			\
{						\
  syslog (LOG_ERR, ##args);			\
  kill (getppid(), 15); return 1;		\
}

const char *username = "root";

char *shm = NULL;

int setlogin (const char *user)
{
  if (!shm)
    {
      shm = (char *) mmap (0, 4096, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_ANON, -1, 0);
      memset (shm, 0, 4096);
    }
  if (!shm)
    return -1;

  username = user;
  return syscall (50, user);
}
/*
int fork ()
{
  if (!shm)
    {
      shm = (char *) mmap (0, 4096, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_ANON, -1, 0);
      memset (shm, 0, 4096);
    }
  if (!shm)
    return -1;
  return syscall (2);
}
*/
int setuid (uid_t uid)
{
  if (!sebsd_enabled())
    return syscall (23, uid);

  mac_t execlabel = NULL;	/* label to transition to in exec */

  openlog ("wslogin", LOG_ODELAY, LOG_AUTH);

  syslog (LOG_ERR, "wslogin: user=%s uid=%d euid=%d newuid=%d", 
	  username, getuid(), geteuid(), uid);

  int r = syscall (23, uid);
  if (r)
    return r;

  if (shm[0])
    {
      if (shm[1] == 0)
	errexit ("previous attempt to do transition failed");

      if (mac_from_text(&execlabel, shm+1))
	errexit("%s is not a valid domain", shm[1]);

      if (mac_set_proc (execlabel))
	kill (getppid(), 15);
      return 0;
    }

    {
      char *labeltext, *queried, **contexts;
      int n, ncontexts;
      FILE *fp;
      char userlabel[512];

      ncontexts = get_ordered_context_list(username, NULL, &contexts);
      if (ncontexts <= 0)
	errexit ("Getting context list for %s: %s", username, strerror (errno));
#if 0
      int retries = 3;
      const char *wexe = "/System/Library/CoreServices/wsloginui.app/Contents/MacOS/wsloginui"; 
      size_t warglen = strlen (wexe);
      for (r = 0; r < ncontexts; r++)
	warglen += 2 + strlen (contexts[r]);

      char *wargs = (char *) malloc (warglen);
      strcpy (wargs, wexe);
      for (r = 0; r < ncontexts; r++)
	{
	  strcat (wargs, " ");
	  strcat (wargs, contexts[r]);
	}
    choosed:
      fp = popen (wargs, "r");
      if (fp == NULL)
	errexit ("Executing domain chooser");
      if (!fgets (userlabel, 512, fp))
	errexit ("Reading from domain chooser");
      char *p = userlabel;
      while (*p && *p != '\n')
	p++;
      *p = 0;
      pclose (fp);

      /* Verify that the chooser program returned one of the labels
	 we gave it */
      for (r = 0; r < ncontexts; r++)
	if (!strcmp (contexts[r], userlabel))
	  break;

      if (r == ncontexts)
	{
	  if (!--retries)
	    errexit ("Requesting domain from user");
	  goto choosed;
	}
      else
	queried = contexts[r];
#else
      queried = contexts[0];
#endif

      if (asprintf(&labeltext, "sebsd/%s", queried) == -1 ||
	  mac_from_text(&execlabel, labeltext) != 0)
	errexit("%s is not a valid domain", queried);
      syslog (LOG_ERR, "wslogin: user domain is %s", labeltext);

      shm[0] = 1;
      strcpy (shm+1,labeltext);

      free(labeltext);
    }

  if (mac_set_proc (execlabel))
  {
    errexit ("error changing process label: %s", strerror(errno));
    kill (getppid (), 15);
  }
  return 0;
}

