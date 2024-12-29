// go:build ignore
#include <vmlinux.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>
#include <builtins.h>
#include "net.h"

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define ETH_HLEN 14
#define AF_INET 2
#define AF_INET6 3
#define MAX_DATA_SIZE 4000
#define MAX_BUF_SIZE 1500
#define PROTOCOL_VEC_LIMIT 3

#define BPF_READ(src)                                     \
    ({                                                    \
        typeof(src) tmp;                                  \
        bpf_probe_read_kernel(&tmp, sizeof(src), &(src)); \
        tmp;                                              \
    })

#define BPF_C_READ(src, a, ...) BPF_CORE_READ(src, a, ##__VA_ARGS__)

#define BPF_U_READ(src, a, ...) BPF_PROBE_READ_USER(src, a, ##__VA_ARGS__)

#define TP_ARGS(dst, idx, ctx)                                                                                       \
    {                                                                                                                \
        void *__p = (void *)ctx + sizeof(struct trace_entry) + sizeof(long int) + idx * (sizeof(long unsigned int)); \
        bpf_probe_read_kernel(dst, sizeof(*dst), __p);                                                               \
    }

#define TP_RET(dst, ctx)                                                         \
    {                                                                            \
        void *__p = (void *)ctx + sizeof(struct trace_entry) + sizeof(long int); \
        bpf_probe_read_kernel(dst, sizeof(*dst), __p);                           \
    }

unsigned long long load_word(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.word");

static const char GET[3] = "GET";
static const char POST[4] = "POST";
static const char PUT[3] = "PUT";
static const char DELETE[6] = "DELETE";
static const char HTTP[4] = "HTTP";

const struct so_event *so_event_unused __attribute__((unused));
const struct upid_t *upid_t_unused __attribute__((unused));
const struct conn_info_evt *conn_info_evt_unused __attribute__((unused));
const struct msg_evt_data *msg_evt_data_unused __attribute__((unused));

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} httpevent SEC(".maps");

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define IP_TCP 6
#define ETH_HLEN 14

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
    __u16 frag_off;

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
    frag_off = __bpf_ntohs(frag_off);
    return frag_off & (IP_MF | IP_OFFSET);
}

static __inline bool can_trace_conn(struct conn_info *conn)
{
    return conn->protocol != ProtocolUnknown;
}

struct data_key
{
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
};

struct data_value
{
    int timestamp;
    // char comm[64];
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct data_key);
    __type(value, struct data_value);
    __uint(max_entries, 2048);
} proc_http_session SEC(".maps");

// SEC("kprobe/tcp_sendmsg")
// int http_tcp_sendmsg(struct pt_regs *ctx)
// {
//     u64 pid_tgid = bpf_get_current_pid_tgid();
//     u64 uid_gid = bpf_get_current_uid_gid();

//     struct data_key key = {};
//     key.src_ip = htonl(saddr);
//     key.dst_ip = htonl(daddr);
//     key.src_port = sport;
//     key.dst_port = htons(dport);

//     struct data_value value = {};
//     value.pid = pid_tgid >> 32;
//     value.uid = (u32)uid_gid;
//     value.gid = uid_gid >> 32;
//     bpf_get_current_comm(value.comm, 64);

//     proc_http_datas.update(&key, &value);
//     return 0;
// }

SEC("socket")
int socket_hander(struct __sk_buff *skb)
{

    u8 verlen;
    u16 proto;
    u32 nhoff = ETH_HLEN;
    // u32 ip_proto = 0;
    u32 tcp_hdr_len = 0;
    u16 tlen;
    u32 payload_offset = 0;
    u32 payload_length = 0;
    u8 hdr_len;

    proto = skb->protocol;
    if (proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    if (ip_is_fragment(skb, nhoff))
        return 0;

    // 获取IP头部的长度
    bpf_skb_load_bytes(skb, ETH_HLEN, &hdr_len, sizeof(hdr_len));
    hdr_len &= 0x0f;
    hdr_len *= 4;

    if (hdr_len < sizeof(struct iphdr))
    {
        return 0;
    }

    // 这行代码计算了TCP头部的偏移量。它将以太网帧头部的长度（nhoff）与IP头部的长度（hdr_len）相加，得到TCP头部的起始位置
    tcp_hdr_len = nhoff + hdr_len;
    bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);

    // 数据包中加载IP头部的总长度字段。IP头部总长度字段表示整个IP数据包的长度，包括IP头部和tcp 头部和数据部分。
    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, tot_len), &tlen, sizeof(tlen));

    // 用于计算TCP头部的长度
    u8 doff;
    bpf_skb_load_bytes(skb, tcp_hdr_len + offsetof(struct tcphdr, ack_seq) + 4, &doff, sizeof(doff));
    doff &= 0xf0;
    doff >>= 4;
    doff *= 4;

    // 以太网帧头部长度、IP头部长度和TCP头部长度相加，得到HTTP请求的数据部分的偏移量，然后通过减去总长度、IP头部长度和TCP头部长度，计算出HTTP请求数据的长度
    payload_offset = ETH_HLEN + hdr_len + doff;
    payload_length = __bpf_ntohs(tlen) - hdr_len - doff;

    char line_buffer[7];
    if (payload_length < 7 || payload_offset < 0)
    {
        return 0;
    }
    bpf_skb_load_bytes(skb, payload_offset, line_buffer, 7);

    if (__bpf_memcmp(line_buffer, GET, 3) != 0 &&
        __bpf_memcmp(line_buffer, POST, 4) != 0 &&
        __bpf_memcmp(line_buffer, PUT, 3) != 0 &&
        __bpf_memcmp(line_buffer, DELETE, 6) != 0 &&
        __bpf_memcmp(line_buffer, HTTP, 4) != 0)
    { // 如果不是http请求，查看是否有 http session
        return 0;
    }
    bpf_printk("%d len %d buffer: %s", payload_offset, payload_length, line_buffer);
    struct iphdr ip;
    bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(struct iphdr));

    struct tcphdr tcp;
    bpf_skb_load_bytes(skb, ETH_HLEN + hdr_len, &tcp, sizeof(struct tcphdr));

    struct so_event e = {};
    bpf_printk("payload_length:%d", payload_length);
    // bpf_skb_load_bytes(skb, payload_offset, e->payload, 150);
    e.src_addr = ip.saddr;
    e.dst_addr = ip.daddr;
    e.src_port = __bpf_ntohs(tcp.source);
    e.dst_port = __bpf_ntohs(tcp.dest);

    bpf_perf_event_output(skb, &httpevent, ((__u64)skb->len << 32) | BPF_F_CURRENT_CPU, &e, sizeof(struct so_event));
    return skb->len;
}

/***********************************************************
 * tc限流
 ***********************************************************/
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1024);
} tc_daddr_map SEC(".maps");

SEC("tc-egress")
unsigned int tc_egress(struct __sk_buff *skb)
{
    __u32 proto;
    proto = skb->protocol;
    if (proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
    {
        return TC_ACT_OK;
    }
    u32 daddr;
    bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), &daddr, 4);

    u32 *valp = bpf_map_lookup_elem(&tc_daddr_map, &daddr);
    bpf_printk("daddr:%d", daddr);
    if (valp)
    {
        bpf_printk("daddr:%d,valp:%d", daddr, *valp);
        return *valp;
    }

    return TC_ACT_OK;
}

/***********************************************************
 * htts嗅探相关
 ***********************************************************/

enum ssl_data_event_type
{
    kSSLRead,
    kSSLWrite
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, const char *);
    __uint(max_entries, 1024);
} active_ssl_write_args_map SEC(".maps");

struct ssl_data_event_t
{
    enum ssl_data_event_type type;
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tid;
    int32_t data_len;
    char data[MAX_DATA_SIZE];
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} tls_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct ssl_data_event_t);
    __uint(max_entries, 1);
} data_buffer_heap SEC(".maps");

static __inline struct ssl_data_event_t *create_ssl_data_event(uint64_t current_pid_tgid)
{
    uint32_t kZero = 0;
    struct ssl_data_event_t *event = bpf_map_lookup_elem(&data_buffer_heap, &kZero);
    if (event == NULL)
    {
        return NULL;
    }

    const uint32_t kMask32b = 0xffffffff;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = current_pid_tgid >> 32;
    event->tid = current_pid_tgid & kMask32b;

    return event;
}

static int process_ssl_data(struct pt_regs *ctx, uint64_t id, enum ssl_data_event_type type,
                            const char *buf)
{
    int len = (int)PT_REGS_RC(ctx);
    if (len < 0)
    {
        return 0;
    }

    struct ssl_data_event_t *event = create_ssl_data_event(id);
    if (event == NULL)
    {
        return 0;
    }

    event->type = type;
    event->data_len = (len < MAX_DATA_SIZE ? (len & (MAX_DATA_SIZE - 1)) : MAX_DATA_SIZE);
    bpf_probe_read_user(event->data, event->data_len, buf);
    bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, event, sizeof(struct ssl_data_event_t));
    return 0;
}

// int SSL_write(SSL *ssl, const void *buf, int num);
SEC("uprobe/SSL_write")
int uprobe_ssL_write(struct pt_regs *ctx)
{
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    //  uint32_t pid = current_pid_tgid >> 32;

    const char *buf = (const char *)PT_REGS_PARM2(ctx); //(const char *)(ctx)->si;
    bpf_map_update_elem(&active_ssl_write_args_map, &current_pid_tgid, &buf, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_write")
int uretprobe_ssl_write(struct pt_regs *ctx)
{
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    // uint32_t pid = current_pid_tgid >> 32;

    const char **buf = bpf_map_lookup_elem(&active_ssl_write_args_map, &current_pid_tgid);
    if (buf != NULL)
    {
        process_ssl_data(ctx, current_pid_tgid, kSSLWrite, *buf);
    }

    bpf_map_delete_elem(&active_ssl_write_args_map, &current_pid_tgid);
    return 0;
}

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, const char *);
    __uint(max_entries, 1024);
} active_ssl_read_args_map SEC(".maps");

SEC("uprobe/SSL_read")
int uprobe_SSL_read(struct pt_regs *ctx)
{
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();

    const char *buf = (const char *)PT_REGS_PARM2(ctx); //(const char *)(ctx)->si;
    bpf_map_update_elem(&active_ssl_read_args_map, &current_pid_tgid, &buf, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int uretprobe_SSL_read(struct pt_regs *ctx)
{
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();

    const char **buf = bpf_map_lookup_elem(&active_ssl_read_args_map, &current_pid_tgid);
    if (buf != NULL)
    {
        process_ssl_data(ctx, current_pid_tgid, kSSLRead, *buf);
    }

    bpf_map_delete_elem(&active_ssl_read_args_map, &current_pid_tgid);

    return 0;
}

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct connect_args);
    __uint(max_entries, 65535);
    __uint(map_flags, 0);
} connect_args_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct accept_args);
    __uint(max_entries, 65535);
    __uint(map_flags, 0);
} accept_args_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct msg_args);
    __uint(max_entries, 65535);
    __uint(map_flags, 0);
} read_args_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct msg_args);
    __uint(max_entries, 65535);
    __uint(map_flags, 0);
} write_args_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct close_args);
    __uint(max_entries, 65535);
    __uint(map_flags, 0);
} close_args_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(uint64_t));
    __uint(value_size, sizeof(struct conn_info));
    __uint(max_entries, 65535);
    __uint(map_flags, 0);
} conn_info_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} conn_evt_rb SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} msg_evt_rb SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct msg_evt_data));
    __uint(max_entries, 1);
    __uint(map_flags, 0);
} msg_data_map SEC(".maps");

static __always_inline struct tcp_sock *get_socket_from_fd(int fd_num)
{
    //  eBPF 提供的一个辅助函数，用于在 eBPF
    //  程序中获取当前正在运行的内核任务（task_struct）。它返回的是一个指向当前任务的指针
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = BPF_READ(task->files);
    struct fdtable *fdt = BPF_READ(files->fdt);
    struct file **fd = BPF_READ(fdt->fd);
    void *file;
    bpf_probe_read(&file, sizeof(file), fd + fd_num);
    struct file *__file = (struct file *)file;
    void *private_data = BPF_READ(__file->private_data);
    if (private_data == NULL)
    {
        return NULL;
    }
    struct socket *socket = (struct socket *)private_data;
    short socket_type = BPF_READ(socket->type);
    struct file *socket_file = BPF_READ(socket->file);
    void *check_file;
    struct tcp_sock *sk;
    struct socket __socket;
    if (socket_file != file)
    {
        sk = (struct tcp_sock *)BPF_READ(socket->file);
    }
    else
    {
        check_file = BPF_READ(socket->file);
        sk = (struct tcp_sock *)BPF_READ(socket->sk);
    }
    if ((socket_type == SOCK_STREAM || socket_type == SOCK_DGRAM) && check_file == file) /*&& __socket.state == SS_CONNECTED */
    {
        return sk;
    }
    return NULL;
}

static void __always_inline export_net_msg(void *ctx, uint32_t seq, const char *buf, uint32_t len, uint64_t tgid_fd, enum message_type msg_type)
{
    bpf_printk("export_net_msg");
    size_t _len = len < MAX_MSG_SIZE ? len : MAX_MSG_SIZE;
    int zero = 0;
    struct msg_evt_data *data = bpf_map_lookup_elem(&msg_data_map, &zero);
    if (!data)
    {
        bpf_printk("data is null");
        return;
    }
    data->meta.msg_type = msg_type;
    data->meta.seq = seq;
    data->meta.tgid_fd = tgid_fd;
    data->meta.ts = bpf_ktime_get_ns();
    size_t len_minus_1 = _len - 1;
    asm volatile("" : "+r"(len_minus_1) :);
    _len = len_minus_1 + 1;
    size_t amount_copied = 0;
    if (len_minus_1 < MAX_MSG_SIZE)
    {
        bpf_probe_read(data->msg, _len, buf);
        amount_copied = _len;
    }
    else if (len_minus_1 < 0x7fffffff)
    {
        bpf_probe_read(data->msg, MAX_MSG_SIZE, buf);
        amount_copied = MAX_MSG_SIZE;
    }
    data->buf_size = amount_copied;
    size_t __len = sizeof(struct msg_evt_meta) + sizeof(uint32_t) + amount_copied;
    bpf_perf_event_output(ctx, &msg_evt_rb, BPF_F_CURRENT_CPU, data, __len);
}

static void __always_inline parse_sock_key_rcv_sk(struct sock *sk, struct sock_key *key)
{
    key->dip = BPF_C_READ(sk, __sk_common.skc_daddr);
    key->sip = BPF_C_READ(sk, __sk_common.skc_rcv_saddr);
    key->sport = BPF_C_READ(sk, __sk_common.skc_num);
    key->dport = bpf_ntohs(BPF_C_READ(sk, __sk_common.skc_dport));
    key->family = BPF_C_READ(sk, __sk_common.skc_family);
}

static __inline uint64_t gen_tgid_fd(uint32_t tgid, int fd)
{
    return ((uint64_t)tgid << 32) | (uint32_t)fd;
}

static __always_inline void process_syscall_connect(void *ctx, long ret, struct connect_args *args, uint64_t pid_tgid, enum Role role)
{
    u32 pid = pid_tgid & 0xffffffff; // 低 32 位表示 PID
    u32 tgid = pid_tgid >> 32;       // 高 32 位表示 TGID

    int ret_fd = args->fd;
    if (ret_fd < 0)
    {
        return;
    }

    struct conn_info c = {};
    struct conn_info *info = &c;
    info->read_bytes = 0;
    info->write_bytes = 0;
    info->conn_id.upid.pid = pid;
    info->conn_id.upid.tgid = tgid;
    info->conn_id.fd = ret_fd;
    info->conn_id.upid.start_time_ticks = args->start_ts;
    info->role = role;

    if (args->addr != NULL)
    {
        bpf_probe_read_user(&info->daddr, sizeof(union sockaddr_t), args->addr);
        struct sockaddr_in *addr4 = (struct sockaddr_in *)args->addr;
        info->daddr.in4.sin_port = bpf_ntohs(info->daddr.in4.sin_port);
        // conn_info.raddr = *((union sockaddr_t*)addr);
    }
    struct tcp_sock *tcp_sk = get_socket_from_fd(ret_fd);

    struct sock_key key;
    parse_sock_key_rcv_sk((struct sock *)tcp_sk, &key);

    bpf_printk("print_sock_key connect port: sport:%d, dport:%d", key.sport, key.dport);
    bpf_printk("print_sock_key connect addr: saddr:%d, daddr:%d", key.sip, key.dip);
    bpf_printk("print_sock_key connect family: family:%u", key.family);

    info->saddr.in4.sin_addr.s_addr = role == Client ? key.sip : key.dip;
    info->saddr.in4.sin_port = role == Client ? key.sport : key.dport;
    info->daddr.in4.sin_addr.s_addr = role == Client ? key.dip : key.sip;
    info->daddr.in4.sin_port = role == Client ? key.dport : key.sport;
    // conn.saddr.in4.sin_family = key.family;
    // conn.daddr.in4.sin_family = key.family;
    if (can_trace_conn(info))
    {
        uint64_t tgid_fd = gen_tgid_fd(tgid, ret_fd);
        // 保存连接信息
        bpf_printk("process_syscall_connect id:%d,tgid:%d,fd:%d", pid_tgid, tgid, ret_fd);
        info->ctype = Connect;
        bpf_map_update_elem(&conn_info_map, &tgid_fd, info, BPF_ANY);
        struct conn_info_evt _evt = {0};
        struct conn_info_evt *evt = &_evt;
        evt->info = *info;
        evt->ts = bpf_ktime_get_ns();
        bpf_perf_event_output(ctx, &conn_evt_rb, BPF_F_CURRENT_CPU, evt, sizeof(struct conn_info_evt));
    }
}

static __always_inline void process_syscall_accpet(void *ctx, int ret_fd, struct accept_args *args, uint64_t pid_tgid, enum Role role)
{
    u32 pid = pid_tgid & 0xffffffff; // 低 32 位表示 PID
    u32 tgid = pid_tgid >> 32;       // 高 32 位表示 TGID

    // int ret_fd = args->fd;
    if (ret_fd < 0)
    {
        return;
    }

    struct conn_info c = {};
    struct conn_info *info = &c;
    info->read_bytes = 0;
    info->write_bytes = 0;
    info->conn_id.upid.pid = pid;
    info->conn_id.upid.tgid = tgid;
    info->conn_id.fd = ret_fd;
    info->conn_id.upid.start_time_ticks = args->start_ts;
    info->role = role;

    if (args->addr != NULL)
    {
        bpf_probe_read_user(&info->daddr, sizeof(union sockaddr_t), args->addr);
        struct sockaddr_in *addr4 = (struct sockaddr_in *)args->addr;
        info->daddr.in4.sin_port = bpf_ntohs(info->daddr.in4.sin_port);
        // conn_info.raddr = *((union sockaddr_t*)addr);
    }
    struct tcp_sock *tcp_sk = get_socket_from_fd(ret_fd);

    struct sock_key key;
    parse_sock_key_rcv_sk((struct sock *)tcp_sk, &key);

    bpf_printk("print_sock_key port: sport:%d, dport:%d", key.sport, key.dport);
    bpf_printk("print_sock_key addr: saddr:%d, daddr:%d", key.sip, key.dip);
    bpf_printk("print_sock_key family: family:%u", key.family);

    info->saddr.in4.sin_addr.s_addr = role == Client ? key.sip : key.dip;
    info->saddr.in4.sin_port = role == Client ? key.sport : key.dport;
    info->daddr.in4.sin_addr.s_addr = role == Client ? key.dip : key.sip;
    info->daddr.in4.sin_port = role == Client ? key.dport : key.sport;
    // conn.saddr.in4.sin_family = key.family;
    // conn.daddr.in4.sin_family = key.family;
    if (can_trace_conn(info))
    {
        uint64_t tgid_fd = gen_tgid_fd(tgid, ret_fd);
        // 保存连接信息
        bpf_printk("process_syscall_accpet id:%d,tgid:%d,fd:%d", pid_tgid, tgid, ret_fd);
        info->ctype = Connect;
        bpf_map_update_elem(&conn_info_map, &tgid_fd, info, BPF_ANY);
        struct conn_info_evt _evt = {0};
        struct conn_info_evt *evt = &_evt;
        evt->info = *info;
        evt->ts = bpf_ktime_get_ns();
        bpf_perf_event_output(ctx, &conn_evt_rb, BPF_F_CURRENT_CPU, evt, sizeof(struct conn_info_evt));
    }
}

static __always_inline void process_syscall_close(void *ctx, struct close_args *args, uint64_t pid_tgid)
{
    if (args->fd < 0)
    {
        // bpf_printk("close syscall args->fd:%d,tgid:%u", args->fd, tgid);
        return;
    }
    u32 pid = pid_tgid & 0xffffffff; // 低 32 位表示 PID
    u32 tgid = pid_tgid >> 32;       // 高 32 位表示 TGID
    uint64_t tgid_fd = gen_tgid_fd(tgid, args->fd);
    // 获取连接信息
    struct conn_info *info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
    if (info == NULL)
    {
        // bpf_printk("close syscall no conn find,tgid:%u,fd:%d",  tgid, args->fd);
        return;
    }
    info->ctype = Close;
    struct conn_info_evt _evt = {0};
    struct conn_info_evt *evt = &_evt;
    evt->info = *info;
    evt->ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &conn_evt_rb, BPF_F_CURRENT_CPU, evt, sizeof(struct conn_info_evt));
    bpf_map_delete_elem(&conn_info_map, &tgid_fd);
}

// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
// SEC("kprobe/__sys_connect")
// int kprobe_sys_connect(struct pt_regs *ctx)
// {
//     uint64_t id = bpf_get_current_pid_tgid();
//     struct connect_args args = {0};
//     const int sockfd = (int)PT_REGS_PARM1(ctx);
//     const struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2(ctx);
//     args.fd = sockfd;
//     args.addr = addr;
//     args.start_ts = bpf_ktime_get_ns();
//     bpf_map_update_elem(&connect_args_map, &id, &args, BPF_ANY);
//     return 0;
// }

// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint_syscalls_sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();

    struct connect_args args = {0};
    TP_ARGS(&args.fd, 0, ctx)
    TP_ARGS(&args.addr, 1, ctx)
    args.start_ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&connect_args_map, &id, &args, BPF_ANY);
    return 0;
}

// /sys/kernel/tracing/events/syscalls/sys_exit_connect/
SEC("tracepoint/syscalls/sys_exit_connect")
int tracepoint__syscalls__sys_exit_connect(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    struct connect_args *args = bpf_map_lookup_elem(&connect_args_map, &pid_tgid);
    if (args != NULL)
    {
        process_syscall_connect(ctx, ctx->ret, args, pid_tgid, Client);
    }
    bpf_map_delete_elem(&connect_args_map, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int tracepoint_syscalls_sys_enter_accept4(struct trace_event_raw_sys_enter *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();
    struct accept_args args = {0};
    TP_ARGS(&args.addr, 1, ctx)
    args.start_ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&accept_args_map, &id, &args, BPF_ANY);
    return 0;
}

// /sys/kernel/tracing/events/syscalls/sys_exit_connect/
SEC("tracepoint/syscalls/sys_exit_accept4")
int tracepoint__syscalls__sys_exit_accept4(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    struct accept_args *args = bpf_map_lookup_elem(&accept_args_map, &pid_tgid);
    if (args != NULL)
    {
        long int ret;
        TP_RET(&ret, ctx);
        process_syscall_accpet(ctx, ret, args, pid_tgid, Server);
    }
    bpf_map_delete_elem(&accept_args_map, &pid_tgid);
    return 0;
}

// 监听客户端连接请求
// int __sys_accept4(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen, int flags)
SEC("kprobe/__sys_accept4")
int kprobe_sys_accept(struct pt_regs *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();
    struct accept_args args = {0};
    const int sockfd = (int)PT_REGS_PARM1(ctx);
    const struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    args.fd = sockfd;
    args.addr = addr;
    args.start_ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&accept_args_map, &id, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/__sys_accept4")
int kretprobe_sys_accept(struct pt_regs *ctx)
{
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    struct accept_args *args = bpf_map_lookup_elem(&accept_args_map, &pid_tgid);
    if (args != NULL)
    {
        int ret_fd = PT_REGS_RC_CORE(ctx);
        process_syscall_accpet(ctx, ret_fd, args, pid_tgid, Server);
    }
    bpf_map_delete_elem(&accept_args_map, &pid_tgid);
    return 0;
}

// SEC("kprobe/__sys_recvfrom")
// int kprobe_sys_recvfrom(struct pt_regs *ctx)
// {
//     bpf_printk("__sys_recvfrom");
//     uint64_t id = bpf_get_current_pid_tgid();
//     const int sockfd = (int)PT_REGS_PARM1(ctx);
//     // const struct user_msghdr *msghdr = (struct user_msghdr *)PT_REGS_PARM2(ctx);
//     struct msg_args args = {0};
//     args.fd = sockfd;
//     // args.iov = BPF_U_READ(msghdr, msg_iov);
//     // args.iovlen = BPF_U_READ(msghdr, msg_iovlen);
//     bpf_map_update_elem(&read_args_map, &id, &args, BPF_ANY);
//     return 0;
// }

// // /sys/kernel/debug/tracing/trace
// SEC("tracepoint/syscalls/sys_exit_recvfrom")
// int tracepoint_syscalls_sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx)
// {
//     uint64_t id = bpf_get_current_pid_tgid();
//     ssize_t bytes_count = ctx->ret;
//     struct msg_args *args = bpf_map_lookup_elem(&read_args_map, &id);
//     if (args != NULL)
//     {
//         // iov（输入 / 输出向量）是一种分散 - 聚集 I / O 操作的数据结构，
//         // 允许应用程序将数据分成多个缓冲区。
//         // 每个缓冲区由一个 iov_base（数据地址）和一个 iov_len（数据长度）组成
//         // 程序通过循环遍历这些缓冲区来读取数据，确保即使数据被分成多个片段，也可以逐一处理。
//         // 获取数据包的协议
//         uint32_t tgid = id >> 32;
//         uint64_t tgid_fd = gen_tgid_fd(tgid, args->fd);
//         // 获取连接信息
//         bpf_printk("sys_exit_recvfrom:%d", tgid_fd);
//         struct conn_info_evt *conn = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
//         if (conn != NULL)
//         {
//             struct iovec iov_cpy;
//             size_t buf_size = 0;
//             bpf_printk("sys_exit_recvfrom tgid_fd:%d", tgid_fd);
//         }
//     }
//     bpf_map_delete_elem(&read_args_map, &id);
//     return 0;
// }

// SEC("kprobe/__x64_sys_read")
// int kprobe_x64_sys_read(struct pt_regs *ctx)
// {
//     // bpf_printk("__x64_sys_read");
//     uint64_t id = bpf_get_current_pid_tgid();
//     const u_int32_t sockfd = (u_int32_t)PT_REGS_PARM1(ctx);
//     // const struct user_msghdr *msghdr = (struct user_msghdr *)PT_REGS_PARM2(ctx);
//     struct msg_args args = {0};
//     args.fd = sockfd;
//     bpf_printk("__x64_sys_read fd:%d", sockfd);
//     // args.iov = BPF_U_READ(msghdr, msg_iov);
//     // args.iovlen = BPF_U_READ(msghdr, msg_iovlen);
//     bpf_map_update_elem(&read_args_map, &id, &args, BPF_ANY);
//     return 0;
// }

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint_syscalls_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();

    struct msg_args args = {0};
    TP_ARGS(&args.fd, 0, ctx)
    TP_ARGS(&args.buf, 1, ctx)
    args.kernel_fn = kSyscallRead;
    bpf_map_update_elem(&write_args_map, &id, &args, BPF_ANY);
    return 0;
}

// /sys/kernel/debug/tracing/trace
SEC("tracepoint/syscalls/sys_exit_write")
int tracepoint_syscalls_sys_exit_write(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();
    ssize_t bytes_count;
    TP_RET(&bytes_count, ctx);
    if (bytes_count < 0)
    {
        return 0;
    }
    struct msg_args *args = bpf_map_lookup_elem(&write_args_map, &id);
    if (args != NULL)
    {
        // iov（输入 / 输出向量）是一种分散 - 聚集 I / O 操作的数据结构，
        // 允许应用程序将数据分成多个缓冲区。
        // 每个缓冲区由一个 iov_base（数据地址）和一个 iov_len（数据长度）组成
        // 程序通过循环遍历这些缓冲区来读取数据，确保即使数据被分成多个片段，也可以逐一处理。
        // 获取数据包的协议
        uint32_t tgid = id >> 32;
        uint64_t tgid_fd = gen_tgid_fd(tgid, args->fd);
        // 获取连接信息

        struct conn_info *conn = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
        if (conn != NULL)
        {
            if (conn->protocol == ProtocolUnset || conn->protocol == ProtocolUnknown)
            {
                enum traffic_protocol before_infer = conn->protocol;
                // 推断协议类型
                struct protocol_message maybe_protocal = infer_protocol(args->buf, bytes_count);
                if (before_infer != maybe_protocal.protocol)
                {
                    struct conn_info_evt _evt = {0};
                    struct conn_info_evt *evt = &_evt;
                    conn->protocol = maybe_protocal.protocol;
                    conn->msg_type = maybe_protocal.type;
                    conn->ctype = ProtocolInfer;
                    evt->info = *conn;
                    evt->ts = bpf_ktime_get_ns();
                    bpf_perf_event_output(ctx, &conn_evt_rb, BPF_F_CURRENT_CPU, evt, sizeof(struct conn_info_evt));
                }
            }
            bpf_printk("sys_exit_write id:%d,tgid:%d,fd:%d", id, tgid, args->fd);
            enum message_type msg_type = conn->role == Client ? Request : Response;
            uint64_t seq = (msg_type == Request ? conn->read_bytes : conn->write_bytes) + 1;
            if (can_trace_conn(conn))
            {
                // 发送数据包
                export_net_msg(ctx, seq, args->buf, bytes_count, tgid_fd, msg_type);
            }
            if (msg_type == Request)
            {
                conn->read_bytes += bytes_count;
            }
            else
            {
                conn->write_bytes += bytes_count;
            }
        }
    }
    bpf_map_delete_elem(&write_args_map, &id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint_syscalls_sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();

    struct msg_args args = {0};
    TP_ARGS(&args.fd, 0, ctx)
    TP_ARGS(&args.buf, 1, ctx)
    args.kernel_fn = kSyscallRead;
    bpf_map_update_elem(&read_args_map, &id, &args, BPF_ANY);
    return 0;
}

// /sys/kernel/debug/tracing/trace
SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint_syscalls_sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    // 用于获取当前执行上下文的进程和线程信息。这个函数返回一个 64 位的值，其中包含了当前的进程 ID 和线程组 ID（PID 和 TGID）。
    uint64_t id = bpf_get_current_pid_tgid();
    ssize_t bytes_count;
    TP_RET(&bytes_count, ctx);
    if (bytes_count < 0)
    {
        return 0;
    }
    struct msg_args *args = bpf_map_lookup_elem(&read_args_map, &id);
    if (args != NULL)
    {
        // iov（输入 / 输出向量）是一种分散 - 聚集 I / O 操作的数据结构，
        // 允许应用程序将数据分成多个缓冲区。
        // 每个缓冲区由一个 iov_base（数据地址）和一个 iov_len（数据长度）组成
        // 程序通过循环遍历这些缓冲区来读取数据，确保即使数据被分成多个片段，也可以逐一处理。
        // 获取数据包的协议
        uint32_t tgid = id >> 32;
        uint64_t tgid_fd = gen_tgid_fd(tgid, args->fd);
        // 获取连接信息
        struct conn_info *conn = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
        if (conn != NULL)
        {
            // 如果协议未知，则推断协议类型
            if (conn->protocol == ProtocolUnset || conn->protocol == ProtocolUnknown)
            {
                enum traffic_protocol before_infer = conn->protocol;
                // 推断协议类型
                struct protocol_message maybe_protocal = infer_protocol(args->buf, bytes_count);
                if (before_infer != maybe_protocal.protocol)
                {
                    struct conn_info_evt _evt = {0};
                    struct conn_info_evt *evt = &_evt;
                    conn->protocol = maybe_protocal.protocol;
                    conn->msg_type = maybe_protocal.type;
                    conn->ctype = ProtocolInfer;
                    evt->info = *conn;
                    evt->ts = bpf_ktime_get_ns();
                    bpf_perf_event_output(ctx, &conn_evt_rb, BPF_F_CURRENT_CPU, evt, sizeof(struct conn_info_evt));
                }
            }
            // 获取数据包的协议
            enum message_type msg_type = conn->role == Client ? Response : Request;
            uint64_t seq = (msg_type == Request ? conn->read_bytes : conn->write_bytes) + 1;
            if (can_trace_conn(conn))
            {
                // 发送数据包
                export_net_msg(ctx, seq, args->buf, bytes_count, tgid_fd, msg_type);
            }
            // 更新连接信息
            if (msg_type == Request)
            {
                conn->read_bytes = conn->read_bytes + bytes_count;
            }
            else
            {
                conn->write_bytes = conn->write_bytes + bytes_count;
            }
            // bpf_printk("read_bytes2 %d", conn->read_bytes);
            // bpf_printk("write_bytes2 %d", conn->write_bytes);
            // bpf_map_update_elem(&conn_info_map, &tgid_fd, conn, BPF_ANY);
        }
    }
    bpf_map_delete_elem(&read_args_map, &id);
    return 0;
}

// int close(int fd);
SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint_syscalls_sys_enter_close(struct trace_event_raw_sys_enter *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();
    struct close_args args = {0};
    TP_ARGS(&args.fd, 0, ctx)
    bpf_map_update_elem(&close_args_map, &id, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int tracepoint_syscalls_sys_exit_close(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();
    struct close_args *args = bpf_map_lookup_elem(&close_args_map, &id);
    if (args != NULL)
    {
        long int ret;
        TP_RET(&ret, ctx);
        process_syscall_close(ctx, args, id);
    }
    bpf_map_delete_elem(&close_args_map, &id);
    return 0;
}

// SEC("kprobe/__sys_recvmsg")
// int kprobe_sys_recvmsg(struct pt_regs *ctx)
// {
//     bpf_printk("__sys_recvmsg");
//     uint64_t id = bpf_get_current_pid_tgid();
//     const int sockfd = (int)PT_REGS_PARM1(ctx);
//     const struct user_msghdr *msghdr = (struct user_msghdr *)PT_REGS_PARM2(ctx);
//     struct msg_args args = {0};
//     args.fd = sockfd;
//     args.iov = BPF_U_READ(msghdr, msg_iov);
//     args.iovlen = BPF_U_READ(msghdr, msg_iovlen);
//     bpf_map_update_elem(&read_args_map, &id, &args, BPF_ANY);
//     return 0;
// }

// SEC("kprobe/__x64_sys_recvmsg")
// int kprobe_sys_x64_recvmsg(struct pt_regs *ctx)
// {
//     bpf_printk("__x64_sys_recvmsg");
//     uint64_t id = bpf_get_current_pid_tgid();
//     const int sockfd = (int)PT_REGS_PARM1(ctx);
//     const struct user_msghdr *msghdr = (struct user_msghdr *)PT_REGS_PARM2(ctx);
//     struct msg_args args = {0};
//     args.fd = sockfd;
//     args.iov = BPF_U_READ(msghdr, msg_iov);
//     args.iovlen = BPF_U_READ(msghdr, msg_iovlen);
//     bpf_map_update_elem(&read_args_map, &id, &args, BPF_ANY);
//     return 0;
// }
// // /sys/kernel/debug/tracing/trace
// SEC("tracepoint/syscalls/sys_exit_recvmsg")
// int tracepoint_syscalls_sys_exit_recvmsg(struct trace_event_raw_sys_exit *ctx)
// {
//     uint64_t id = bpf_get_current_pid_tgid();
//     ssize_t bytes_count = ctx->ret;
//     bpf_printk("tracepoint_syscalls_sys_recvmsg2");
//     struct msg_args *args = bpf_map_lookup_elem(&read_args_map, &id);
//     if (args != NULL)
//     {
//         // iov（输入 / 输出向量）是一种分散 - 聚集 I / O 操作的数据结构，
//         // 允许应用程序将数据分成多个缓冲区。
//         // 每个缓冲区由一个 iov_base（数据地址）和一个 iov_len（数据长度）组成
//         // 程序通过循环遍历这些缓冲区来读取数据，确保即使数据被分成多个片段，也可以逐一处理。
//         // 获取数据包的协议
//         uint32_t tgid = id >> 32;
//         uint64_t tgid_fd = gen_tgid_fd(tgid, args->fd);
//         // 获取连接信息
//         bpf_printk("tracepoint_syscalls_sys_recvmsg tgid_fd:%d", tgid_fd);
//         struct conn_info_evt *conn = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
//         if (conn != NULL)
//         {
//             struct iovec iov_cpy;
//             size_t buf_size = 0;
//             bpf_printk("tracepoint_syscalls_sys_exit_recvmsg");
//         }
//     }
//     bpf_map_delete_elem(&read_args_map, &id);
//     return 0;
// }

// SEC("kprobe/do_readv")
// int kprobe_do_readv(struct pt_regs *ctx)
// {
//     bpf_printk("kprobe_do_readv");
//     uint64_t id = bpf_get_current_pid_tgid();
//     const int sockfd = (int)PT_REGS_PARM1(ctx);
//     struct msg_args args = {0};
//     args.fd = sockfd;
//     bpf_map_update_elem(&read_args_map, &id, &args, BPF_ANY);
//     return 0;
// }

// SEC("kretprobe/do_readv")
// int kretprobe_do_readv(struct pt_regs *ctx)
// {
//     uint64_t id = bpf_get_current_pid_tgid();
//     ssize_t bytes_count = PT_REGS_RC_CORE(ctx);
//     struct msg_args *args = bpf_map_lookup_elem(&read_args_map, &id);
//     if (args != NULL)
//     {
//         uint32_t tgid = id >> 32;
//         uint64_t tgid_fd = gen_tgid_fd(tgid, args->fd);
//         // 获取连接信息
//         bpf_printk("do_readv tgid_fd:%d", tgid_fd);
//         struct conn_info_evt *conn = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
//         if (conn != NULL)
//         {
//             struct iovec iov_cpy;
//             size_t buf_size = 0;
//             bpf_printk("do_readv tgid_fd:%d", tgid_fd);
//         }
//     }
//     bpf_map_delete_elem(&read_args_map, &id);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_accept4")
// int tracepoint__syscalls__sys_exit_accept4(struct trace_event_sys_exit *ctx)
// {
//     uint64_t pid_tgid = bpf_get_current_pid_tgid();
//     struct connect_args *args = bpf_map_lookup_elem(&connect_args_map, &pid_tgid);
//     if (args != NULL)
//     {
//         process_syscall_connect(ctx, ctx->ret, args, pid_tgid, Server);
//     }
//     bpf_map_delete_elem(&connect_args_map, &pid_tgid);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_accept4")
// int tracepoint__syscalls__sys_exit_accept4(struct trace_event_sys_exit *ctx)
// {
//     uint64_t pid_tgid = bpf_get_current_pid_tgid();
//     struct connect_args *args = bpf_map_lookup_elem(&connect_args_map, &pid_tgid);
//     if (args != NULL)
//     {
//         process_syscall_connect(ctx, ctx->ret, args, pid_tgid, Server);
//     }
//     bpf_map_delete_elem(&connect_args_map, &pid_tgid);
//     return 0;
// }

/***********************************************************
 * 统计相关
 ***********************************************************/

struct ipv4_key_t
{
    u32 saddr;
    u32 daddr;
    //  u16 lport;
    // u16 dport;
};

struct bpf_map_def SEC("maps") ipv4_send_bytes = {
    .type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
    .key_size = sizeof(struct ipv4_key_t),
    .value_size = sizeof(u64),
    .max_entries = 1024,
};

//  tcp_sendmsg(struct sock *sk,struct msghdr *msg, size_t size)   size
SEC("kprobe/tcp_sendmsg")
int ktcp_sendmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (sk == NULL)
    {
        return 0;
    }

    u16 family, lport, dport;
    u32 src_ip4, dst_ip4;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);

    if (family != AF_INET)
    {
        return 0;
    }
    bpf_probe_read(&lport, sizeof(lport), &sk->__sk_common.skc_num);
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read(&src_ip4, sizeof(src_ip4), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&dst_ip4, sizeof(dst_ip4), &sk->__sk_common.skc_daddr);

    struct ipv4_key_t ipv4_key = {};
    ipv4_key.saddr = src_ip4;
    ipv4_key.daddr = dst_ip4;
    if (src_ip4 == dst_ip4)
    {
        return 0;
    }
    u64 *valp = bpf_map_lookup_elem(&ipv4_send_bytes, &ipv4_key);
    if (!valp)
    {
        u64 initval = 0;
        bpf_map_update_elem(&ipv4_send_bytes, &ipv4_key, &initval, BPF_ANY);
        return 0;
    }
    long size = PT_REGS_PARM3(ctx);
    __sync_fetch_and_add(valp, size);
    return 0;
}

struct bpf_map_def SEC("maps") ipv4_recv_bytes = {
    .type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
    .key_size = sizeof(struct ipv4_key_t),
    .value_size = sizeof(u64),
    .max_entries = 1024,
};

// tcp_cleanup_rbuf(struct sock *sk, int copied)   copied
SEC("kprobe/tcp_cleanup_rbuf")
int ktcp_cleanup_rbuf(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (sk == NULL)
    {
        return 0;
    }
    // u32 pid = bpf_get_current_pid_tgid() >> 32;
    //  FILTER_PID

    u16 family, lport, dport;
    u32 src_ip4, dst_ip4;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);

    if (family != AF_INET)
    {
        return 0;
    }
    bpf_probe_read(&lport, sizeof(lport), &sk->__sk_common.skc_num);
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read(&src_ip4, sizeof(src_ip4), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&dst_ip4, sizeof(dst_ip4), &sk->__sk_common.skc_daddr);

    struct ipv4_key_t ipv4_key = {};
    ipv4_key.saddr = src_ip4;
    ipv4_key.daddr = dst_ip4;

    if (src_ip4 == dst_ip4)
    {
        return 0;
    }
    u64 *valp = bpf_map_lookup_elem(&ipv4_recv_bytes, &ipv4_key);
    if (!valp)
    {
        u64 initval = 0;
        bpf_map_update_elem(&ipv4_recv_bytes, &ipv4_key, &initval, BPF_ANY);
        return 0;
    }
    long size = PT_REGS_PARM2(ctx);
    __sync_fetch_and_add(valp, size);
    return 0;
}

char __license[] SEC("license") = "GPL";