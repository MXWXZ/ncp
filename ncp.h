#ifndef __NCP_NCP_H__
#define __NCP_NCP_H__

#define NETLINK_TEST 17
#define MAGIC_NUMBER "rainhurt"
#define MAGIC_NUMBER_RESP "phpisbst"
#define MAGIC_NUMBER_END "seeunext"

#define log_info(fmt, arg...) \
    printk("[ncp - INFO] %s:%d " fmt, __FUNCTION__, __LINE__, ##arg)
#define log_warn(fmt, arg...) \
    printk("[ncp - WARN] %s:%d " fmt, __FUNCTION__, __LINE__, ##arg)
#define log_err(fmt, arg...) \
    printk("[ncp - ERR] %s:%d " fmt, __FUNCTION__, __LINE__, ##arg)

#endif
