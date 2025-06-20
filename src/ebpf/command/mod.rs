mod attach;
mod load;
mod map;

use alloc::string::{String, ToString};

use ebpf_command::command::*;
pub use map::HermitMapFile;

use crate::ebpf::{GLOBAL_EBPF_PROGS, HermitKernelAux};
use crate::tracepoint::trace_point_manager;

#[allow(non_camel_case_types)]
pub trait eBPFCommandExec {
	fn execute(self) -> Result<String, String>;
}

impl eBPFCommandExec for eBPFCommand<'_> {
	fn execute(self) -> Result<String, String> {
		let res = match self {
			eBPFCommand::LoadProgram(load_program) => load_program.execute(),
			eBPFCommand::RemoveProgram(name) => {
				let mut programs = GLOBAL_EBPF_PROGS.lock();
				if programs.remove(name).is_none() {
					return Err("Program not found".to_string());
				}
				log::trace!("eBPF program '{name}' removed successfully");
				Ok("".to_string())
			}
			eBPFCommand::GetTPInfo => {
				let info = crate::tracepoint::tracepoint_infomation();
				Ok(info)
			}
			eBPFCommand::AttachProgram(attach_program) => attach_program.execute(),
			eBPFCommand::DetachProgram(detach_program) => detach_program.execute(),
			eBPFCommand::EnableTP(tp_id) => {
				let manager = trace_point_manager();
				let tp_map = manager.tracepoint_map();
				let tp = tp_map
					.get(&tp_id)
					.ok_or_else(|| "Tracepoint not found".to_string())?;
				log::trace!("Enabling tracepoint event: {}:{}", tp.system(), tp.name());
				tp.enable();
				Ok("".to_string())
			}
			eBPFCommand::DisableTP(tp_id) => {
				let manager = trace_point_manager();
				let tp_map = manager.tracepoint_map();
				let tp = tp_map
					.get(&tp_id)
					.ok_or_else(|| "Tracepoint not found".to_string())?;
				log::trace!("Disabling tracepoint event: {}:{}", tp.system(), tp.name());
				tp.disable();
				Ok("".to_string())
			}
			eBPFCommand::CreateMap(createmap) => createmap.execute(),
			eBPFCommand::UpdateMap(updatemap) => updatemap.execute(),
			eBPFCommand::FreezeMap(freezemap_fd) => {
				bpf_basic::map::bpf_map_freeze::<HermitKernelAux>(freezemap_fd).unwrap();
				Ok("".to_string())
			}
			eBPFCommand::DeleteMap(delete_map_fd) => map::execute_delete_map(delete_map_fd),
			eBPFCommand::MapGetNextKey(map_get_next_key) => map_get_next_key.execute(),

			eBPFCommand::LookupMap(lookup_map) => lookup_map.execute(),
		};
		match res {
			Ok(msg) => Ok("OK:".to_string() + &msg),
			Err(e) => Err("ERROR:".to_string() + &e),
		}
	}
}
