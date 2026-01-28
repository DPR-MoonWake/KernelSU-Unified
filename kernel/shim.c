#include <linux/version.h>
#include <linux/compat.h>
#include <linux/fs.h>

// unity build idea from backslashxx, not full, we only use it for shim ksu hooks

#include "allowlist.h"
#include "arch.h"
#include "ksu.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "kernel_compat.h"
#include "supercalls.h"
#include "sucompat.h"
#include "setuid_hook.h"
#include "selinux/selinux.h"
#include "throne_tracker.h"

#if (defined(CONFIG_KSU_MANUAL_HOOK) &&                                        \
     LINUX_VERSION_CODE < KERNEL_VERSION(6, 8, 0))
#include "lsm_hook.c"
#elif (defined(CONFIG_KSU_MANUAL_HOOK) &&                                      \
       LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0))
// + ksu_handle_setresuid hook for 6.8+
#include "pkg_observer.c"
#endif
