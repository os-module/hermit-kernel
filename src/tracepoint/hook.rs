use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;

use hermit_sync::SpinMutex;
use rbpf::EbpfVmRaw;
use tracepoint::{TracePoint, TracePointCallBackFunc};

use crate::ebpf::JITMem;
use crate::io::{Error, Result};
use crate::tracepoint::TraceLock;

#[derive(Debug)]
pub struct TracepointPerfEvent {
	tp: &'static TracePoint<TraceLock<()>>,
	ebpf_list: SpinMutex<Vec<u64>>,
}

impl TracepointPerfEvent {
	pub fn new(tp: &'static TracePoint<TraceLock<()>>) -> TracepointPerfEvent {
		TracepointPerfEvent {
			tp,
			ebpf_list: SpinMutex::new(Vec::new()),
		}
	}
}

impl TracepointPerfEvent {
	pub fn bind_ebpf(&self, bpf_prog: Vec<u8>) -> Result<u64> {
		static CALLBACK_ID: AtomicU64 = AtomicU64::new(0);

		let mut vm = EbpfVmRaw::new(None).map_err(|e| {
			log::error!("create ebpf vm failed: {e:?}");
			Error::EINVAL
		})?;

		let bpf_prog = Box::leak(bpf_prog.into_boxed_slice());
		vm.set_program(bpf_prog).unwrap();

		let helperset = crate::ebpf::helper::ebpf_helper_list();
		for (id, helper) in helperset.iter() {
			vm.register_helper(*id, *helper).unwrap();
		}

		// create a callback to execute the ebpf prog
		let callback;

		#[cfg(target_arch = "x86_64")]
		{
			log::warn!("Using JIT compilation for BPF program on x86_64 architecture");
			let jit_mem = Box::new(crate::ebpf::JITMem::alloc());
			let jit_mem = Box::leak(jit_mem);
			let jit_mem_addr = core::ptr::from_ref::<JITMem>(jit_mem) as usize;
			vm.set_jit_exec_memory(jit_mem).unwrap();
			vm.jit_compile().unwrap();
			callback = Box::new(TracePointPerfCallBack::new(bpf_prog, vm, jit_mem_addr));
		}
		#[cfg(not(target_arch = "x86_64"))]
		{
			log::warn!("Using interpreter for BPF program on non-x86_64 architecture");
			vm.register_allowed_memory(0..u64::MAX);
			callback = Box::new(TracePointPerfCallBack::new(bpf_prog, vm));
		};
		let id = CALLBACK_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
		self.tp.register_raw_callback(id as usize, callback);

		log::info!(
			"Registered BPF program for tracepoint: {}:{} with ID: {}",
			self.tp.system(),
			self.tp.name(),
			id
		);
		// Store the ID in the ebpf_list for later cleanup
		self.ebpf_list.lock().push(id);
		Ok(id)
	}

	pub fn unbind_ebpf(&self, id: u64) -> Result<()> {
		log::info!(
			"Unregistering BPF program for tracepoint: {}:{} with ID: {}",
			self.tp.system(),
			self.tp.name(),
			id
		);
		self.tp.unregister_raw_callback(id as usize);
		self.ebpf_list.lock().retain(|&x| x != id);
		Ok(())
	}

	pub fn ebpf_progs_len(&self) -> usize {
		self.ebpf_list.lock().len()
	}
}

impl Drop for TracepointPerfEvent {
	fn drop(&mut self) {
		log::info!(
			"Dropping TracepointPerfEvent for {}:{}",
			self.tp.system(),
			self.tp.name()
		);
		// Unregister all callbacks associated with this tracepoint event
		let mut ebpf_list = self.ebpf_list.lock();
		for id in ebpf_list.iter() {
			self.tp.unregister_raw_callback(*id as usize);
		}
		// Disable the tracepoint
		self.tp.disable();
		ebpf_list.clear();
	}
}

pub struct TracePointPerfCallBack {
	bpf_prog_file: &'static [u8],
	vm: EbpfVmRaw<'static>,
	#[cfg(target_arch = "x86_64")]
	jit_mem_addr: usize,
}

unsafe impl Send for TracePointPerfCallBack {}
unsafe impl Sync for TracePointPerfCallBack {}

impl TracePointPerfCallBack {
	#[cfg(target_arch = "x86_64")]
	fn new(bpf_prog_file: &'static [u8], vm: EbpfVmRaw<'static>, jit_mem_addr: usize) -> Self {
		Self {
			bpf_prog_file,
			vm,
			jit_mem_addr,
		}
	}
	#[cfg(not(target_arch = "x86_64"))]
	fn new(bpf_prog_file: &'static [u8], vm: EbpfVmRaw<'static>) -> Self {
		Self { bpf_prog_file, vm }
	}
}

impl Drop for TracePointPerfCallBack {
	fn drop(&mut self) {
		let bpf_prog = unsafe {
			Box::from_raw(core::slice::from_raw_parts_mut(
				self.bpf_prog_file.as_ptr().cast_mut(),
				self.bpf_prog_file.len(),
			))
		};
		drop(bpf_prog);
		#[cfg(target_arch = "x86_64")]
		{
			let jit_mem = unsafe { Box::from_raw(self.jit_mem_addr as *mut JITMem) };
			drop(jit_mem);
		}
	}
}

impl TracePointCallBackFunc for TracePointPerfCallBack {
	fn call(&self, entry: &[u8]) {
		// ebpf needs a mutable slice
		let entry =
			unsafe { core::slice::from_raw_parts_mut(entry.as_ptr().cast_mut(), entry.len()) };
		let res = if cfg!(target_arch = "x86_64") {
			unsafe { self.vm.execute_program_jit(entry) }
		} else {
			self.vm.execute_program(entry)
		};
		// log::warn!("Executing BPF program result: {res:?}");
		if res.is_err() {
			log::error!("tracepoint callback error: {res:?}");
		}
	}
}
