use alloc::string::String;

use hermit_sync::{Lazy, SpinMutex, SpinMutexGuard};
use tracepoint::TracingEventsManager;

use crate::println;

static TRACE_POINT_MANAGER: Lazy<TracingEventsManager<TraceLock<()>>> = Lazy::new(|| {
	// Initialize the tracing events manager.
	static_keys::global_init();
	tracepoint::global_init_events::<TraceLock<()>>().unwrap()
});

pub fn trace_point_manager() -> &'static TracingEventsManager<TraceLock<()>> {
	&TRACE_POINT_MANAGER
}

static TRACE_PIPE: SpinMutex<tracepoint::TracePipe> =
	SpinMutex::new(tracepoint::TracePipe::new(1024));

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

pub mod tracepoint_test {
	use tracepoint::{KernelTraceOps, define_event_trace, define_trace_point, paste};

	use super::{TRACE_PIPE, TraceLock};
	use crate::println;
	use crate::time::{SystemTime, timespec};

	// define_trace_point!(Mutex, TEST);
	struct Kops;

	impl KernelTraceOps for Kops {
		fn cpu_id() -> u32 {
			0
		}
		fn current_pid() -> u32 {
			1
		}
		fn time_now() -> u64 {
			let time = timespec::from(SystemTime::now());
			time.into_usec().unwrap_or(0) as u64
		}
		fn trace_pipe_push_record(format: alloc::string::String) {
			let mut pipe = TRACE_PIPE.lock();
			pipe.push_record(format);
		}
	}
	define_event_trace!(
		TraceLock,
		Kops,
		TEST,
		(a: u32, b: u32),
		format_args!("Hello from tracepoint! a={}, b={}", a, b)
	);

	define_event_trace!(
		TraceLock,
		Kops,
		TEST2,
		(a: u32, b: u32),
		format_args!("Hello from tracepoint2! a={}, b={}", a, b)
	);

	pub fn test_trace(a: u32, b: u32) {
		trace_TEST(a, b);
		trace_TEST2(a, b);
		println!("Tracepoint TEST called with a={}, b={}", a, b);
	}
}

pub fn print_trace_records() {
	let mut buf = [0u8; 1024];
	let pipe = TRACE_PIPE.lock();
	let size = pipe.read_at(&mut buf, 0).unwrap();
	if size == 0 {
		println!("No trace records found.");
		return;
	}
	let records = String::from_utf8_lossy(&buf[..size]);
	println!("Trace records:\n{}", records);
}
