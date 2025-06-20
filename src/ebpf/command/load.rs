use alloc::string::{String, ToString};
use alloc::sync::Arc;

use bpf_basic::EBPFPreProcessor;
use ebpf_command::command::LoadProgram;

use crate::ebpf::command::{HermitMapFile, eBPFCommandExec};
use crate::ebpf::{GLOBAL_EBPF_PROGS, HermitKernelAux};

pub struct HermitEbpfProgram {
	preprocessor: EBPFPreProcessor,
}

impl Drop for HermitEbpfProgram {
	fn drop(&mut self) {
		unsafe {
			for ptr in self.preprocessor.get_raw_file_ptr() {
				let file = Arc::from_raw((*ptr as *const u8).cast::<HermitMapFile>());
				drop(file);
			}
		}
	}
}

impl eBPFCommandExec for LoadProgram<'_> {
	fn execute(self) -> Result<String, String> {
		let mut programs = GLOBAL_EBPF_PROGS.lock();
		if programs.contains_key(self.name) {
			return Err("Program already loaded".to_string());
		}
		log::trace!("eBPF program '{}' loaded successfully", self.name);

		let LoadProgram {
			name, program_data, ..
		} = self;
		let pre_process =
			bpf_basic::EBPFPreProcessor::preprocess::<HermitKernelAux>(program_data.to_vec())
				.unwrap();

		programs.insert(name.to_string(), pre_process);
		Ok("".to_string())
	}
}
