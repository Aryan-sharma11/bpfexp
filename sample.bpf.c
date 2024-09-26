// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ARG_LEN 128

#define MAX_STR_ARR_ELEM 20
#define STR_T 10UL
#define STR_ARR_T 11UL
#define STR_ARR_T 11UL
#define MAX_BUFFER_SIZE 32768
#define MAX_STRING_SIZE 256
#define MAX_COMBINED_LENGTH 4096
#define MAX_ARG_STRINGS 0x7FFFFFFF
#define MAX_BUFFERS 1
#define DATA_BUF_TYPE 0
#define PATH_BUFFER 0
#define __user
#define TASK_COMM_LEN 80
#define MAX_ENTRIES 10240
#define PATHNAME_SIZE	 256
#define EPERM 13
struct outer_key {
  u32 pid_ns;
  u32 mnt_ns;
};

struct arg_Key{
  u32 pid ;
  u32 tgid;
};
struct argVal{
  char argsArray[10][20];
};
struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, struct arg_Key);
 __type(value, struct argVal);
} values SEC(".maps");

#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries)
    

#define READ_KERN(ptr)                                     \
    ({                                                     \
        typeof(ptr) _val;                                  \
        __builtin_memset((void *)&_val, 0, sizeof(_val));  \
        bpf_probe_read((void *)&_val, sizeof(_val), &ptr); \
        _val;                                              \
    })

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);  // Only one entry to store the count
    __type(key, int);
    __type(value, int);
} count_map SEC(".maps");


char LICENSE[] SEC("license") = "Dual BSD/GPL";

typedef struct {
  u32 pid;
  u32 pid_ns;
  u32 mnt_ns;
  char comm[80];
  u32 daddr;
} event;

struct mapkey{
  u32 pid; 
  u32 mntid; 
  char path[255];
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, struct mapkey);
    __type(value, u8);  // The value is a single byte (u8)
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} path_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, struct mapkey);  // Composite key of mntid + pid + somepath
    __type(value, u8); 
    __uint(pinning, LIBBPF_PIN_BY_NAME);            // Value is a u8 integer
} args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");
#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
    struct {                                                        \
  __uint(type, _type);                                              \
  __type(key, _key_type);                                           \
  __type(value, _value_type);                                       \
  __uint(max_entries, _max_entries);                                \
} _name SEC(".maps");   

// Force emitting struct event into the ELF.
const event *unused __attribute__((unused));
typedef struct buffers
{   
    u8 buf[MAX_BUFFER_SIZE];
} bufs_t;

BPF_PERCPU_ARRAY(bufs, bufs_t, 4);
BPF_PERCPU_ARRAY(bufs_offset, u32, 4);

// static __always_inline bufs_t *get_buffer(int buf_type)
// {
//     return bpf_map_lookup_elem(&bufs, &buf_type);
// }


static __always_inline u32 get_task_pid_vnr(struct task_struct *task) {
  struct pid *pid = BPF_CORE_READ(task, thread_pid);
  unsigned int level = BPF_CORE_READ(pid, level);
  return BPF_CORE_READ(pid, numbers[level].nr);
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task) {
  struct task_struct *group_leader = BPF_CORE_READ(task, group_leader);
  return get_task_pid_vnr(group_leader);
}
static __always_inline void set_buffer_offset(int buf_type, u32 off)
{
    bpf_map_update_elem(&bufs_offset, &buf_type, &off, BPF_ANY);
}
static __always_inline u32 *get_buffer_offset(int buf_type)
{
    return bpf_map_lookup_elem(&bufs_offset, &buf_type);
}

static __always_inline bufs_t *get_buffer(int buf_type)
{
    return bpf_map_lookup_elem(&bufs, &buf_type);
}

static __always_inline int save_str_arr_to_buffer( struct arg_Key key, const char __user *const __user *ptr)

{
  int *j;
  int z = 0 ;
  bpf_map_update_elem(&count_map, &z , &z , BPF_ANY);
  struct argVal  val;
    #pragma unroll
    for (int i = 0; i < 5; i++)
    {   
        j = bpf_map_lookup_elem(&count_map, &z);
          if (!j){
            bpf_printk("Failed to loarray \n");
            break; 
          }
        const char *const *curr_ptr = (void *)&ptr[i] ;
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), curr_ptr);
        int k = *j;
        if (*j < 0 || *j >= 4)
            break;
          if (argp)
              {
                bpf_probe_read_str(val.argsArray[k], sizeof(val.argsArray[0]), argp);
                 k++ ; // Increment the index
              }
        *j = k;
        bpf_map_update_elem(&count_map, &z, j, BPF_ANY);
    }
    bpf_map_update_elem(&values, &key, &val, BPF_ANY);
    return 0;
}


SEC("kprobe/__x64_sys_execve")
int kprobe__execve(struct pt_regs *ctx)
{   
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
      u32 mnt_ns_try = 4026533222;
      u32 pid_ns_try = 4026533612 ;
      
      u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;
      u32 mnt_ns = BPF_CORE_READ(t, nsproxy, mnt_ns, ns).inum;

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    unsigned long argv = READ_KERN(PT_REGS_PARM2(ctx2));
    int x;
    const char *kernel_ptr;
    int i;
      bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
        return 0;
    struct arg_Key keyArg ;

     keyArg.pid = bpf_get_current_pid_tgid() >> 32;
     keyArg.tgid = bpf_get_current_pid_tgid();  
     save_str_arr_to_buffer(keyArg,(const char *const *)argv);
    
    return 0;
}


SEC("lsm/bprm_check_security")
int BPF_PROG(enforce_bprm, struct linux_binprm *bprm, int ret) {

  //create map 
 
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();

  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;
  u32 mnt_ns = BPF_CORE_READ(t, nsproxy, mnt_ns, ns).inum;
  int x;
  unsigned long a_start; 
  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  char srcval[MAX_STRING_SIZE];

  unsigned int num = BPF_CORE_READ(bprm , argc);

  bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
        return -1;

    u32 *off = get_buffer_offset(DATA_BUF_TYPE);
    if (off == NULL)
        return -1;

    void *data = bufs_p->buf;
    if(data == NULL){
        return 0;
    }
  
    struct arg_Key keyArg ;
     keyArg.pid = bpf_get_current_pid_tgid() >> 32;
     keyArg.tgid = bpf_get_current_pid_tgid();

    struct argVal *val ;
    val = bpf_map_lookup_elem(&values, &keyArg);
    if(num < 0) {
      return 0;
    }
    if(num > 10){
      return 0;
    }
    struct mapkey try, next_key;

    if (val) {
      // #pragma unroll 
      for( int i = 1 ; i< num && i<10; i++ ){
          bpf_printk("Argurment %d : %s\n", i,  val->argsArray[i]);
          struct mapkey arg;
          __builtin_memset(&arg, 0, sizeof(arg));
          arg.pid = pid_ns;
          arg.mntid = mnt_ns;
          // bpf_probe_read
          bpf_probe_read_str(arg.path, sizeof(arg.path),  val->argsArray[i]);
          // bpf_probe_read(arg.path, sizeof(arg.path), val->argsArray[i]);
          unsigned int *x = bpf_map_lookup_elem(&args_map ,&arg);
          bpf_printk("arg path =%s  x = %u",arg.path, *x);
          bpf_printk("arg size %d", sizeof(struct mapkey) );
          bpf_printk("arg  %u  , %u ", arg.mntid , arg.pid );
          
          if(x){
            bpf_printk("argument matched");
          } else {
            bpf_printk("argument not matched");
            return -EPERM;
          }  
      }

    }

  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;

  return 0;
}
