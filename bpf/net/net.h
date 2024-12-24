#ifndef __KPROBE_H__
#define __KPROBE_H__

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
    Unset = 0,
    Unknown,
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

struct conn_info_evt
{
    struct conn_id conn_id;
    // IP address of the local endpoint.
    union sockaddr_t saddr;
    union sockaddr_t daddr;
    enum traffic_protocol protocol;
};

#endif