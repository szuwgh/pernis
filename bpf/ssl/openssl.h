#include <vmlinux.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>
#include <builtins.h>

#define MAX_DATA_SIZE 4000

struct nested_ssl_fd
{
    int fd;
    uint32_t syscall_len;
};

static int get_fd_symaddrs(uint32_t tgid, void *ssl)
{
    const void **rbio_ptr_addr = ssl + SSL_ST_RBIO;
    void *rbio_ptr;
    bpf_probe_read_user(&rbio_ptr, sizeof(rbio_ptr), rbio_ptr_addr);
    const int *rbio_num_addr = rbio_ptr + BIO_ST_NUM;
    int rbio_num;
    bpf_probe_read_user(&rbio_num, sizeof(rbio_num), rbio_num_addr);
    return rbio_num;
}

enum ssl_data_event_type
{
    kSSLRead,
    kSSLWrite
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(uint64_t));
    __uint(value_size, sizeof(struct nested_ssl_fd));
    __uint(max_entries, 65535);
    __uint(map_flags, 0);
} ssl_user_space_call_map SEC(".maps");

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
    uint64_t id = bpf_get_current_pid_tgid();
    //  uint32_t pid = current_pid_tgid >> 32;

    const char *buf = (const char *)PT_REGS_PARM2(ctx); //(const char *)(ctx)->si;
    bpf_map_update_elem(&active_ssl_write_args_map, &id, &buf, BPF_ANY);
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