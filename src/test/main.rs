
#![no_std]
#![no_main]
use cty::*;

// use one of the preludes
// use redbpf_probes::kprobes::prelude::*;
// use redbpf_probes::xdp::prelude::*;
// use redbpf_probes::socket_filter::prelude::*;

// Use the types you're going to share with userspace, eg:
// use bpf_tracing::test::SomeEvent;

program!(0xFFFFFFFE, "GPL");

// The maps and probe functions go here, eg:
//
// #[map("syscall_events")]
// static mut syscall_events: PerfMap<SomeEvent> = PerfMap::with_max_entries(1024);
//
// #[kprobe("syscall_enter")]
// fn syscall_enter(regs: Registers) {
//   let pid_tgid = bpf_get_current_pid_tgid();
//   ...
//
//   let event = SomeEvent {
//     id: pid_tgid >> 32,
//     ...
//   };
//   unsafe { syscall_events.insert(ctx, &event) };
// }
