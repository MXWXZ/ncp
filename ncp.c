#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/spinlock.h>
#include <net/ip.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include "ncp.h"

char* p_from = "";
u32 g_from = 0;
module_param_named(from, p_from, charp, 0);
MODULE_PARM_DESC(from, "from ip filter");
char* p_to = "";
u32 g_to = 0;
module_param_named(to, p_to, charp, 0);
MODULE_PARM_DESC(to, "to ip filter");
u32 g_bufsize = 100;
module_param_named(buf, g_bufsize, uint, 0);
MODULE_PARM_DESC(buf, "netlink buffer size");

struct ncp_msg {
    u32 saddr;
    u16 sport;
    u32 daddr;
    u16 dport;
    u8 protocol;
};

dev_t g_nl_dev;                   // netlink dev id
struct class* g_nl_cls = NULL;    // netlink class
struct sock* g_nl_sk = NULL;      // netlink sock
int g_nl_pid = -1;                // netlink pid
u32 g_nl_seq = 0;                 // netlink sequence number
struct ncp_msg* g_nl_buf = NULL;  // netlink buffer
u32 g_nl_bufcnt = 0;              // netlink buffer cnt
DEFINE_SPINLOCK(g_nl_lock);

static unsigned int ncp_input_hook(void* priv, struct sk_buff* skb,
                                   const struct nf_hook_state* state);
static unsigned int ncp_output_hook(void* priv, struct sk_buff* skb,
                                    const struct nf_hook_state* state);
static int nl_send(struct ncp_msg* msg);
static int nl_send_buf(void);
static int nl_send_data(char* msg, int len);
static void nl_recv(struct sk_buff* skb);
static int ncp_get_port(const struct sk_buff* skb, u16* sport, u16* dport);
bool check_protocol(u8 proto);
static u32 ip2u32(char* ip);

struct nf_hook_ops ncp_hook_ops[] = {
    {
        .hook = ncp_input_hook,
        .pf = PF_INET,
        .hooknum = NF_INET_PRE_ROUTING,  // ENTRANCE
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = ncp_output_hook,
        .pf = PF_INET,
        .hooknum = NF_INET_POST_ROUTING,  // EXIT
        .priority = NF_IP_PRI_FIRST,
    }};

static u32 ip2u32(char* ip) {
    u32 a, b, c, d;
    sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d);
    if (a > 255 || b > 255 || c > 255 || d > 255) {
        log_warn("invalid ip format\n");
        return 0;
    }
    return (a << 24) + (b << 16) + (c << 8) + d;
}

static int ncp_init(void) {
    struct netlink_kernel_cfg nl_cfg;

    if (strlen(p_from))
        g_from = htonl(ip2u32(p_from));
    if (strlen(p_to))
        g_to = htonl(ip2u32(p_to));
    log_info("param: from=%s(%u) to=%s(%u) buf=%u\n", p_from, g_from, p_to,
             g_to, g_bufsize);

    if (g_bufsize)
        g_nl_buf = kmalloc(sizeof(struct ncp_msg) * g_bufsize, GFP_ATOMIC);

    // init netfilter
    if (unlikely(nf_register_net_hooks(&init_net, ncp_hook_ops,
                                       ARRAY_SIZE(ncp_hook_ops)))) {
        log_warn("netfilter register fail\n");
        return -1;
    }

    // init netlink
    if (unlikely(alloc_chrdev_region(&g_nl_dev, 0, 1, "stone-alloc-dev"))) {
        log_err("register dev id error\n");
        return -1;
    }
    g_nl_cls = class_create(THIS_MODULE, "stone-class");
    if (unlikely(IS_ERR(g_nl_cls))) {
        log_err("create class error\n");
        return -1;
    }
    if (unlikely(!device_create(g_nl_cls, NULL, g_nl_dev, "", "ncp"))) {
        log_err("create device error\n");
        return -1;
    }
    nl_cfg.groups = 0;
    nl_cfg.flags = 0;
    nl_cfg.input = nl_recv;
    nl_cfg.cb_mutex = NULL;
    nl_cfg.bind = NULL;
    nl_cfg.unbind = NULL;
    nl_cfg.compare = NULL;
    g_nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, &nl_cfg);
    if (unlikely(!g_nl_sk)) {
        log_err("create netlink sk error\n");
        return -1;
    }

    log_info("ncp module init\n");
    return 0;
}

static void ncp_exit(void) {
    if (likely(g_nl_pid != -1)) {
        spin_lock(&g_nl_lock);
        if (nl_send_buf())
            nl_send_data(MAGIC_NUMBER_END, strlen(MAGIC_NUMBER_END));
        g_nl_pid = -1;
        spin_unlock(&g_nl_lock);
    }
    nf_unregister_net_hooks(&init_net, ncp_hook_ops, ARRAY_SIZE(ncp_hook_ops));
    if (likely(g_nl_sk)) {
        netlink_kernel_release(g_nl_sk);
    }
    if (likely(g_nl_cls && g_nl_dev)) {
        device_destroy(g_nl_cls, g_nl_dev);
        class_destroy(g_nl_cls);
        unregister_chrdev_region(g_nl_dev, 1);
    }
    log_info("ncp module exit\n");
}

static int nl_send_data(char* msg, int len) {
    struct sk_buff* out_skb;
    struct nlmsghdr* nlhdr;

    if (unlikely(NULL == g_nl_sk || -1 == g_nl_pid)) {
        g_nl_bufcnt = 0;
        log_warn("receiver not found\n");
        return -1;
    }

    out_skb = nlmsg_new(len, GFP_ATOMIC);
    if (unlikely(!out_skb)) {
        log_warn("can not allocate skb\n");
        return -1;
    }

    nlhdr = nlmsg_put(out_skb, 0, ++g_nl_seq, NLMSG_DONE, len, 0);
    if (unlikely(!nlhdr)) {
        log_warn("nlmsg_put error\n");
        return -1;
    }

    NETLINK_CB(out_skb).portid = 0;
    NETLINK_CB(out_skb).dst_group = 0;

    memcpy(nlmsg_data(nlhdr), msg, len);
    if (unlikely(nlmsg_unicast(g_nl_sk, out_skb, g_nl_pid))) {
        log_warn("nlmsg_unicast error\n");
        return -1;
    }

    return 0;
}

static int nl_send_buf(void) {
    int ret = 0;
    if (unlikely(!g_nl_bufcnt))
        return 1;
    ret = nl_send_data((char*)g_nl_buf, sizeof(struct ncp_msg) * g_nl_bufcnt);
    g_nl_bufcnt = 0;
    return ret;
}

// no need to lock for nl_send
static int nl_send(struct ncp_msg* msg) {
    static const int len = sizeof(struct ncp_msg);
    int ret = 0;
    if (unlikely(!g_bufsize))
        return nl_send_data((char*)msg, sizeof(struct ncp_msg));

    spin_lock(&g_nl_lock);
    memcpy(g_nl_buf + g_nl_bufcnt, msg, len);
    ++g_nl_bufcnt;

    if (g_nl_bufcnt == g_bufsize)  // full
        ret = nl_send_buf();
    spin_unlock(&g_nl_lock);

    return ret;
}

static void nl_recv(struct sk_buff* skb) {
    struct nlmsghdr* nlh = nlmsg_hdr(skb);
    char* str = (char*)nlmsg_data(nlh);

    if (strcmp(str, MAGIC_NUMBER_END) == 0) {  // exit magic number check
        spin_lock(&g_nl_lock);
        if (nl_send_buf())
            nl_send_data(MAGIC_NUMBER_END, strlen(MAGIC_NUMBER_END));
        spin_unlock(&g_nl_lock);
        log_info("connection close: [%d]\n", g_nl_pid);
        g_nl_pid = -1;
        g_nl_bufcnt = 0;
        return;
    } else if (strcmp(str, MAGIC_NUMBER) != 0) {  // income magic number check
        log_warn("illegal connection from: [%d]\n", g_nl_pid);
        return;
    }
    g_nl_seq = nlh->nlmsg_seq - 1;
    g_nl_pid = nlh->nlmsg_pid;
    g_nl_bufcnt = 0;
    log_info("connection from: [%d]\n", g_nl_pid);

    nl_send_data(MAGIC_NUMBER_RESP,
                 strlen(MAGIC_NUMBER_RESP));  // send response magic number
}

static unsigned int ncp_input_hook(void* priv, struct sk_buff* skb,
                                   const struct nf_hook_state* state) {
    struct iphdr* iph = NULL;  // IP header
    struct ncp_msg msg;

    iph = ip_hdr(skb);
    if (unlikely(!iph))
        return NF_ACCEPT;
    if (!check_protocol(iph->protocol))
        return NF_ACCEPT;

    // source = target, handle in exit
    if (iph->saddr == iph->daddr)
        return NF_ACCEPT;

    if ((g_from && iph->saddr != g_from) || (g_to && iph->daddr != g_to))
        return NF_ACCEPT;

    msg.protocol = iph->protocol;
    msg.saddr = ntohl(iph->saddr);
    msg.daddr = ntohl(iph->daddr);
    ncp_get_port(skb, &msg.sport, &msg.dport);
    if (likely(g_nl_pid != -1))
        nl_send(&msg);

    return NF_ACCEPT;
}

static unsigned int ncp_output_hook(void* priv, struct sk_buff* skb,
                                    const struct nf_hook_state* state) {
    struct iphdr* iph;
    struct ncp_msg msg;

    iph = ip_hdr(skb);
    if (unlikely(!iph))
        return NF_ACCEPT;
    if (!check_protocol(iph->protocol))
        return NF_ACCEPT;

    if ((g_from && iph->saddr != g_from) || (g_to && iph->daddr != g_to))
        return NF_ACCEPT;

    msg.protocol = iph->protocol;
    msg.saddr = ntohl(iph->saddr);
    msg.daddr = ntohl(iph->daddr);
    ncp_get_port(skb, &msg.sport, &msg.dport);
    if (likely(g_nl_pid != -1))
        nl_send(&msg);

    return NF_ACCEPT;
}

bool check_protocol(u8 proto) {
    switch (proto) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            // TODO: Add more proto
            return true;
        default:
            return false;
    }
}

static int ncp_get_port(const struct sk_buff* skb, u16* sport, u16* dport) {
    struct iphdr* iph = NULL;
    struct tcphdr* tcph = NULL;
    struct udphdr* udph = NULL;

    iph = ip_hdr(skb);
    if (unlikely(!iph)) {
        log_warn("ip header null\n");
        return 1;
    }

    switch (iph->protocol) {
        case IPPROTO_TCP: {
            tcph = tcp_hdr(skb);
            if (unlikely(!tcph)) {
                log_warn("tcp header null\n");
                return 1;
            }

            *dport = ntohs(tcph->dest);
            *sport = ntohs(tcph->source);
            break;
        }
        case IPPROTO_UDP: {
            udph = udp_hdr(skb);
            if (unlikely(!udph)) {
                log_warn("udp header null\n");
                return 1;
            }
            *dport = ntohs(udph->dest);
            *sport = ntohs(udph->source);
            break;
        }
        // TODO: Add more proto
        default:
            return 1;
    }
    return 0;
}

MODULE_LICENSE("GPL");
module_init(ncp_init);
module_exit(ncp_exit);