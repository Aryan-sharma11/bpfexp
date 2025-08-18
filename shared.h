
// #include "vmlinux.h"

// struct outer_hash {
//   __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
//   __uint(max_entries, 256);
//   __uint(key_size, sizeof(struct outer_key));
//   __uint(value_size, sizeof(u32));
//   __uint(pinning, LIBBPF_PIN_BY_NAME);
// };

// struct outer_hash kubearmor_containers SEC(".maps");