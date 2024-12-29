#ifndef __KPROBE_H__
#define __KPROBE_H__

#define MAX_MSG_SIZE 30720

enum kernel_function
{
    kSyscallRead,
    kSyscallRecvMsg,
};

struct connect_args
{
    const struct sockaddr *addr;
    int32_t fd;
    uint64_t start_ts;
};

struct accept_args
{
    const struct sockaddr *addr;
    int32_t fd;
    uint64_t start_ts;
};

struct close_args
{
    uint32_t fd;
};

struct msg_args
{
    enum kernel_function kernel_fn;
    int32_t fd;
    // send()/recv()/write()/read()
    const char *buf;
    // sendmsg()/recvmsg()/writev()/readv()
    const struct iovec *iov;
    size_t iovlen;
};

struct sock_key
{
    uint32_t sip;
    uint32_t dip;
    uint32_t sport;
    uint32_t dport;
    uint32_t family;
};

struct so_event
{
    u32 src_addr;
    u32 dst_addr;
    u16 src_port;
    u16 dst_port;
    u32 payload_length;
};

struct upid_t
{

    uint32_t pid;
    uint32_t tgid;
    uint64_t start_time_ticks;
};

enum traffic_protocol
{
    ProtocolUnset = 0,
    ProtocolUnknown,
    ProtocolHTTP,
    ProtocolHTTP2
};

enum Role
{
    Client,
    Server
};

struct conn_id
{
    // pid/tgid.
    struct upid_t upid;
    // The file descriptor to the opened network connection.
    int32_t fd;
    // Unique id of the conn_id (timestamp).
    uint64_t tsid;
};

union sockaddr_t
{
    struct sockaddr_in in4;
    struct sockaddr_in6 in6;
};

enum message_type
{
    MsgUnknown,
    Request,
    Response
};

enum conn_type
{
    Connect,
    Close,
    ProtocolInfer,
};

struct conn_info
{
    uint32_t read_bytes;
    uint32_t write_bytes;
    struct conn_id conn_id;
    // IP address of the local endpoint.
    union sockaddr_t saddr;
    union sockaddr_t daddr;
    enum traffic_protocol protocol;
    enum message_type msg_type;
    enum conn_type ctype;
    enum Role role;
};

struct conn_info_evt
{
    struct conn_info info;
    uint64_t ts;
};

struct msg_evt_meta
{
    uint64_t tgid_fd;
    uint64_t ts;
    uint32_t seq;
    enum message_type msg_type;
};

struct msg_evt_data
{
    struct msg_evt_meta meta;
    uint32_t buf_size;
    char msg[MAX_MSG_SIZE];
};

static __always_inline enum message_type
is_http_protocol(const char *old_buf, size_t count)
{
    if (count < 5)
    {
        return 0;
    }
    char buf[4] = {};
    bpf_probe_read_user(buf, 4, old_buf);
    if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P')
    {
        return Response;
    }
    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T')
    {
        return Request;
    }
    if (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D')
    {
        return Request;
    }
    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T')
    {
        return Request;
    }
    return MsgUnknown;
}

struct protocol_message
{
    enum traffic_protocol protocol;
    enum message_type type;
};

static __always_inline struct protocol_message
infer_protocol(const char *buf, size_t count)
{
    struct protocol_message pro;
    pro.protocol = ProtocolUnknown;
    pro.type = MsgUnknown;
    if (is_http_protocol(buf, count))
    {
        pro.protocol = ProtocolHTTP;
    }
    return pro;
};
#endif