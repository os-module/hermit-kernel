use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Debug;

use ahash::RandomState;
use bpf_basic::EBPFPreProcessor;
use bpf_basic::map::{PerCpuVariants, PerCpuVariantsOps};
use hashbrown::HashMap;
use hermit_sync::{Lazy, SpinMutex};

pub mod helper;
mod mem;
pub mod server;
pub use mem::JITMem;
pub mod command;

use crate::ebpf::command::HermitMapFile;
use crate::time::{SystemTime, timespec};

static GLOBAL_EBPF_PROGS: Lazy<SpinMutex<HashMap<String, EBPFPreProcessor, RandomState>>> =
	Lazy::new(|| SpinMutex::new(HashMap::with_hasher(RandomState::with_seeds(0, 0, 0, 0))));

static GLOBAL_EBPF_MAPS: Lazy<SpinMutex<HashMap<u32, Arc<HermitMapFile>, RandomState>>> =
	Lazy::new(|| SpinMutex::new(HashMap::with_hasher(RandomState::with_seeds(0, 0, 0, 0))));

pub struct HermitKernelAux;
impl bpf_basic::KernelAuxiliaryOps for HermitKernelAux {
	fn get_unified_map_from_ptr<F, R>(ptr: *const u8, func: F) -> bpf_basic::Result<R>
	where
		F: FnOnce(&mut bpf_basic::map::UnifiedMap) -> bpf_basic::Result<R>,
	{
		let map = unsafe { Arc::from_raw(ptr.cast::<HermitMapFile>()) };
		let mut unified_map = map.map().lock();
		let ret = func(&mut unified_map);
		drop(unified_map);
		// avoid double free
		let _ = Arc::into_raw(map);
		ret
	}

	fn get_unified_map_from_fd<F, R>(map_fd: u32, func: F) -> bpf_basic::Result<R>
	where
		F: FnOnce(&mut bpf_basic::map::UnifiedMap) -> bpf_basic::Result<R>,
	{
		let map = GLOBAL_EBPF_MAPS.lock().get(&map_fd).unwrap().clone();
		let mut map = map.map().lock();
		func(&mut map)
	}

	fn get_unified_map_ptr_from_fd(map_fd: u32) -> bpf_basic::Result<*const u8> {
		let map = GLOBAL_EBPF_MAPS.lock().get(&map_fd).unwrap().clone();
		Ok(Arc::into_raw(map).cast::<u8>())
	}

	fn transmute_buf(ptr: *const u8, size: usize) -> bpf_basic::Result<&'static [u8]> {
		unsafe { Ok(core::slice::from_raw_parts(ptr, size)) }
	}

	fn transmute_buf_mut(ptr: *mut u8, size: usize) -> bpf_basic::Result<&'static mut [u8]> {
		unsafe {
			// This is unsafe and should be used with caution
			Ok(core::slice::from_raw_parts_mut(ptr, size))
		}
	}

	fn current_cpu_id() -> u32 {
		0
	}

	fn perf_event_output(
		_ctx: *mut core::ffi::c_void,
		_fd: u32,
		_flags: u32,
		_data: &[u8],
	) -> bpf_basic::Result<()> {
		todo!()
	}

	fn string_from_user_cstr(ptr: *const u8) -> bpf_basic::Result<String> {
		let cstr = unsafe { core::ffi::CStr::from_ptr(ptr.cast::<i8>()) };
		cstr.to_str()
			.map(|s| s.to_string())
			.map_err(|_| bpf_basic::BpfError::InvalidArgument)
	}

	fn ebpf_write_str(str: &str) -> bpf_basic::Result<()> {
		print!("{}", str);
		Ok(())
	}

	fn ebpf_time_ns() -> bpf_basic::Result<u64> {
		let time = timespec::from(SystemTime::now());
		Ok(time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64)
	}
}

#[derive(Debug)]
pub struct HermitPerCpu;

impl PerCpuVariantsOps for HermitPerCpu {
	fn create<T: Clone + Sync + Send + 'static>(
		value: T,
	) -> Option<Box<dyn bpf_basic::map::PerCpuVariants<T>>> {
		Some(Box::new(HermitPerCpuVariants(vec![value])))
	}

	fn num_cpus() -> u32 {
		1
	}
}

pub struct HermitPerCpuVariants<T>(Vec<T>);

impl<T> Debug for HermitPerCpuVariants<T> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "HermitPerCpuVariants<>")
	}
}

impl<T: Clone + Sync + Send + 'static> PerCpuVariants<T> for HermitPerCpuVariants<T> {
	fn get(&self) -> &T {
		&self.0[0] // Assuming single CPU for now
	}

	fn get_mut(&self) -> &mut T {
		unsafe { &mut *self.0.as_ptr().cast_mut() }
	}

	unsafe fn force_get(&self, cpu: u32) -> &T {
		self.0.get(cpu as usize).expect("CPU index out of bounds")
	}

	unsafe fn force_get_mut(&self, cpu: u32) -> &mut T {
		unsafe { &mut *self.0.as_ptr().add(cpu as usize).cast_mut() }
	}
}
