/* Suite version information for procps utilities
 * Copyright (c) 1995 Martin Schulze <joey@infodrom.north.de>
 * Ammended by cblake to only export the function symbol.
 *
 * Modified by Albert Cahalan, ????-2003
 *
 * Redistributable under the terms of the
 * GNU Library General Public License; see COPYING
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include "version.h"


/* Linux kernel version information for procps utilities
 * Copyright (c) 1996 Charles Blake <cblake@bbn.com>
 */
#include <sys/utsname.h>

#define LINUX_VERSION(x,y,z)   (0x10000*(x) + 0x100*(y) + z)

void init_Linux_version(void) {
    int x = 0, y = 0, z = 0;	/* cleared in case sscanf() < 3 */
    int version_string_depth;

#ifdef __linux__
    static struct utsname uts;

    if (uname(&uts) == -1)	/* failure implies impending death */
	exit(1);

    version_string_depth = sscanf(uts.release, "%d.%d.%d", &x, &y, &z);
#else
    FILE *fp;
    char buf[256];

    if ( (fp=fopen("/proc/version","r")) == NULL) {
      fprintf(stderr, "Cannot find /proc/version - is /proc mounted?\n");
      exit(1);
	}
    if (fgets(buf, 256, fp) == NULL) {
      fprintf(stderr, "Cannot read kernel version from /proc/version\n");
      fclose(fp);
      exit(1);
    }
    fclose(fp);
    version_string_depth = sscanf(buf, "Linux version %d.%d.%d", &x, &y, &z);
#endif /* __linux__ */

    if ((version_string_depth < 2) ||		 /* Non-standard for all known kernels */
       ((version_string_depth < 3) && (x < 3))) /* Non-standard for 2.x.x kernels */
#ifdef __linux__
	fprintf(stderr,		/* *very* unlikely to happen by accident */
		"Non-standard uts for running kernel:\n"
		"release %s=%d.%d.%d gives version code %d\n",
		uts.release, x, y, z, LINUX_VERSION(x,y,z));
#else
	fprintf(stderr,		/* *very* unlikely to happen by accident */
		"%s=%d.%d.%d gives version code %d\n",
		buf, x, y, z, LINUX_VERSION(x,y,z));
#endif /* __linux__ */
    linux_version_code = LINUX_VERSION(x, y, z);
}
