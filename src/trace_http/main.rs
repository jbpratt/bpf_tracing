// binaries are loaded into the kernel, not executed
#![no_std]
#![no_main]
use cty::*;

use redbpf_macros::{map, program, xdp};
use redbpf_probes::xdp::prelude::*;
use redbpf_probes::xdp::{MapData, PerfMap};

#[derive(Debug)]
pub struct RequestInfo {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
}

// Specifying which kernel version this program is compatible and what license it is distributed
// under. 0xFFFFFFFE means 'any kernel version'. The license is specified because the VM will make
// some APIs available or not depending on it. This also generates some boilerplate to compile and
// load correctly
program!(0xFFFFFFFE, "GPL");

// BPF API provides several data structures (maps) to store and aggregate data across program
// invocations and to exchange data with user space. `PerfMap` allows storage of data in
// `mmap()`ed shared memory accessible by user space. The `map` attribute is used to name the map
// and place it in a special ELF section called `maps/<name>` of the resulting binary (for user
// space loader to find and initialize)
#[map("requests")]
static mut requests: PerfMap<RequestInfo> = PerfMap::with_max_entries(1024);

// the 'xdp' attribute macro is mainly used here to signal to the bytecode loader that this
// function is an XDP program. The function takes a XdpContext and returns a XdpAction. The context
// is just a higher level abstraction over the underlying `xdp_md` pointer provided by the BPF VM.
// The macro used here transparently maps between the two types. XdpAction indicates what should be
// done with the data, passed, dropped, or redirected to another interface.
#[xdp]
pub extern "C" fn trace_http(ctx: XdpContext) -> XdpResult {
    // Match on transport protocol that is TCP
    let (ip, transport, data) = match (ctx.ip(), ctx.transport(), ctx.data()) {
        (Ok(ip), Ok(t @ Transport::TCP(_)), Ok(data)) => (unsafe { *ip }, t, data),
        _ => return Ok(XdpAction::Pass),
    };

    // read data into buffer to analyze
    let buff: [u8; 6] = match data.read() {
        Ok(b) => b,
        _ => return Ok(XdpAction::Pass),
    };

    // if buff request method is one of the following, then it looks like an HTTP request
    if &buff[..4] != b"GET "
        && &buff[..4] != b"HEAD"
        && &buff[..4] != b"PUT "
        && &buff[..4] != b"POST"
        && &buff[..6] != b"DELETE"
    {
        return Ok(XdpAction::Pass);
    }

    // parse the request into a `RequestInfo` struct
    let info = RequestInfo {
        saddr: ip.saddr,
        daddr: ip.daddr,
        sport: transport.source(),
        dport: transport.dest(),
    };

    unsafe {
        // insert the request into the PerfMap
        requests.insert(
            &ctx,
            // `data.len()` bytes from the current packet should be inserted in the map immediately
            // following the `RequestInfo` data. `data.offset()` indicates the offset at which the
            // HTTP data starts (following the Ethernet, IP and TCP headers)
            &MapData::with_payload(info, data.offset() as u32, data.len() as u32),
        )
    };

    Ok(XdpAction::Pass)
}
