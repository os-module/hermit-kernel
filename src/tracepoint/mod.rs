mod hook;
use alloc::string::String;

use hermit_sync::{Lazy, SpinMutex, SpinMutexGuard};
pub use hook::TracepointPerfEvent;
use tracepoint::{KernelTraceOps, TraceEntryParser, TracePipeOps, TracingEventsManager};

use crate::core_id;
use crate::syscalls::sys_msleep;
use crate::time::{SystemTime, timespec};

static TRACE_POINT_MANAGER: Lazy<TracingEventsManager<TraceLock<()>>> = Lazy::new(|| {
	// Initialize the tracing events manager.
	static_keys::global_init();
	tracepoint::global_init_events::<TraceLock<()>>().unwrap()
});

pub fn trace_point_manager() -> &'static TracingEventsManager<TraceLock<()>> {
	&TRACE_POINT_MANAGER
}

pub static TRACE_RAW_PIPE: SpinMutex<tracepoint::TracePipeRaw> =
	SpinMutex::new(tracepoint::TracePipeRaw::new(16));

pub static TRACE_CMDLINE_CACHE: SpinMutex<tracepoint::TraceCmdLineCache> =
	SpinMutex::new(tracepoint::TraceCmdLineCache::new(4));

#[derive(Debug)]
pub struct TraceLock<T>(SpinMutex<T>);

impl<T> TraceLock<T> {
	pub const fn new(data: T) -> Self {
		Self(SpinMutex::new(data))
	}
	pub fn lock(&self) -> SpinMutexGuard<'_, T> {
		self.0.lock()
	}
}

unsafe impl lock_api::RawMutex for TraceLock<()> {
	#[allow(clippy::declare_interior_mutable_const)]
	const INIT: Self = Self(SpinMutex::new(()));

	type GuardMarker = lock_api::GuardSend;

	fn lock(&self) {
		let lock = self.0.lock();
		core::mem::forget(lock);
	}

	fn try_lock(&self) -> bool {
		let lock = self.0.try_lock();
		lock.map(core::mem::forget).is_some()
	}

	unsafe fn unlock(&self) {
		unsafe {
			self.0.force_unlock();
		}
	}

	fn is_locked(&self) -> bool {
		self.0.is_locked()
	}
}

pub struct Kops;

impl KernelTraceOps for Kops {
	fn cpu_id() -> u32 {
		core_id()
	}

	fn current_pid() -> u32 {
		u32::MAX
	}

	fn time_now() -> u64 {
		let time = timespec::from(SystemTime::now());
		time.into_usec().unwrap_or(0) as u64
	}

	fn trace_pipe_push_raw_record(buf: &[u8]) {
		let mut pipe = TRACE_RAW_PIPE.lock();
		pipe.push_event(buf.to_vec());
	}

	fn trace_cmdline_push(_pid: u32) {
		// let cmdline_cache = TRACE_CMDLINE_CACHE.lock();
		// // get current process name
		// cmdline_cache.insert(pid, cmdline);
	}
}

fn print_trace_records() {
	let manager = trace_point_manager();
	let tracepoint_map = manager.tracepoint_map();
	let trace_cmdline_cache = TRACE_CMDLINE_CACHE.lock();

	let mut snapshot = TRACE_RAW_PIPE.lock().snapshot();
	print!("{}", snapshot.default_fmt_str());
	loop {
		let mut flag = false;
		if let Some(event) = snapshot.peek() {
			let trace_str =
				TraceEntryParser::parse::<Kops, _>(&*tracepoint_map, &trace_cmdline_cache, event);
			print!("{}", trace_str);
			flag = true;
		}
		if flag {
			snapshot.pop();
		} else {
			break;
		}
	}
}

/// Get all tracepoint information as a string.
pub fn tracepoint_infomation() -> String {
	let manager = trace_point_manager();
	let tp_map = manager.tracepoint_map();
	let mut info = String::new();
	for (_id, tp) in tp_map.iter() {
		let tp_format = tp.print_fmt();
		info += &tp_format;
		info += "\n";
	}
	info
}

pub extern "C" fn read_tracepoint_records(_: usize) {
	loop {
		sys_msleep(1000 * 60); // Sleep for 60 seconds
		print_trace_records();
	}
}

pub extern "C" fn ebpf_task(_: usize) {
	log::warn!("Run eBPF loop...");
	#[cfg(feature = "udp")]
	crate::ebpf::server::ebpf_server();
}
