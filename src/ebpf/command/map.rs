use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::sync::atomic::AtomicU32;

use bpf_basic::BpfError;
use bpf_basic::linux_bpf::BpfMapType;
use bpf_basic::map::{BpfMapGetNextKeyArg, BpfMapMeta, BpfMapUpdateArg, UnifiedMap};
use ebpf_command::command::*;
use hermit_sync::SpinMutex;

use crate::ebpf::command::eBPFCommandExec;
use crate::ebpf::{GLOBAL_EBPF_MAPS, HermitKernelAux, HermitPerCpu};

#[derive(Debug)]
pub struct HermitMapFile {
	map: SpinMutex<UnifiedMap>,
}

impl HermitMapFile {
	pub fn new(map: UnifiedMap) -> Self {
		HermitMapFile {
			map: SpinMutex::new(map),
		}
	}

	pub fn map(&self) -> &SpinMutex<UnifiedMap> {
		&self.map
	}
}

impl eBPFCommandExec for CreateMap {
	fn execute(self) -> Result<String, String> {
		let name = unsafe {
			core::ffi::CStr::from_ptr(self.map_name.as_ptr().cast::<i8>())
				.to_str()
				.map_err(|_| "Invalid map name".to_string())?
				.to_string()
		};
		let map_type = BpfMapType::try_from(self.map_type).unwrap();
		let map_meta = BpfMapMeta {
			map_type,
			key_size: self.key_size,
			value_size: self.value_size,
			max_entries: self.max_entries,
			_map_flags: self.map_flags,
			_map_name: name.clone(),
		};
		let map = bpf_basic::map::bpf_map_create::<HermitPerCpu>(map_meta)
			.map_err(|e| format!("Failed to create eBPF map: {e}"))?;
		let hermit_map = HermitMapFile::new(map);

		static MAP_FD: AtomicU32 = AtomicU32::new(0);
		let fd = MAP_FD.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
		GLOBAL_EBPF_MAPS.lock().insert(fd, Arc::new(hermit_map));
		log::trace!("eBPF map '{name}' created successfully with fd {fd}");
		Ok(fd.to_string())
	}
}

impl eBPFCommandExec for UpdateMap<'_> {
	fn execute(self) -> Result<String, String> {
		let update_map_arg = BpfMapUpdateArg {
			map_fd: self.map_fd,
			key: self.key.as_ptr() as _,
			value: self.value.as_ptr() as _,
			flags: self.flags,
		};
		bpf_basic::map::bpf_map_update_elem::<HermitKernelAux>(update_map_arg).unwrap();
		log::trace!("eBPF map with fd {} updated successfully", self.map_fd);
		Ok("".to_string())
	}
}

pub fn execute_delete_map(map_fd: u32) -> Result<String, String> {
	let map = GLOBAL_EBPF_MAPS.lock().remove(&map_fd);
	match map {
		Some(_map) => Ok("".to_string()),
		None => Err(format!("eBPF map with fd {map_fd} not found")),
	}
}

impl eBPFCommandExec for MapGetNextKey<'_> {
	fn execute(self) -> Result<String, String> {
		let key_size = GLOBAL_EBPF_MAPS
			.lock()
			.get(&self.map_fd)
			.ok_or_else(|| format!("eBPF map with fd {} not found", self.map_fd))?
			.map()
			.lock()
			.map_meta()
			.key_size;
		let mut key_buf = vec![0u8; key_size as _];
		let arg = BpfMapGetNextKeyArg {
			map_fd: self.map_fd,
			key: self.key.map(|buf| buf.as_ptr() as _),
			next_key: key_buf.as_mut_ptr() as _,
		};
		let res = bpf_basic::map::bpf_map_get_next_key::<HermitKernelAux>(arg);
		if let Err(BpfError::NotFound) = res {
			return Ok("".to_string());
		};
		log::trace!(
			"eBPF map with fd {} next key retrieved successfully",
			self.map_fd
		);
		let mut key_buf = core::mem::ManuallyDrop::new(key_buf);
		let key = unsafe {
			String::from_raw_parts(key_buf.as_mut_ptr(), key_buf.len(), key_buf.capacity())
		};
		Ok(key)
	}
}

impl eBPFCommandExec for LookupMap<'_> {
	fn execute(self) -> Result<String, String> {
		let value_size = GLOBAL_EBPF_MAPS
			.lock()
			.get(&self.map_fd)
			.ok_or_else(|| format!("eBPF map with fd {} not found", self.map_fd))?
			.map()
			.lock()
			.map_meta()
			.value_size;
		let mut value_buf = vec![0u8; value_size as _];
		let arg = BpfMapUpdateArg {
			map_fd: self.map_fd,
			key: self.key.as_ptr() as _,
			value: value_buf.as_mut_ptr() as _,
			flags: self.flags, // No flags for lookup
		};
		bpf_basic::map::bpf_lookup_elem::<HermitKernelAux>(arg).unwrap();
		log::trace!(
			"eBPF map with fd {} value retrieved successfully",
			self.map_fd
		);
		let mut value_buf = core::mem::ManuallyDrop::new(value_buf);
		let value = unsafe {
			String::from_raw_parts(
				value_buf.as_mut_ptr(),
				value_buf.len(),
				value_buf.capacity(),
			)
		};
		Ok(value)
	}
}
