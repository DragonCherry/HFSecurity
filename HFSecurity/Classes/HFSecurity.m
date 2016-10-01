//
//  HFSecurity.m
//  HFSecurity
//
//  Created by DragonCherry on 7/11/16.
//  Copyright © 2016 CocoaPods. All rights reserved.
//

#include "HFSecurity.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <string.h>

@implementation HFSecurity

- (BOOL)isDebugging {
    size_t size = sizeof(struct kinfo_proc);
    struct kinfo_proc info;
    int ret, name[4];
    memset(&info, 0, sizeof(struct kinfo_proc));
    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();
    if ((ret = (sysctl(name, 4, &info, &size, NULL, 0)))) {
        if (ret) {
            return true;
        }
    }
    if (info.kp_proc.p_flag & P_TRACED) {
        return true;
    } else {
        return false;
    }
}

@end