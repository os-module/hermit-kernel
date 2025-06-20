use alloc::collections::btree_map::BTreeMap;
use alloc::string::{String, ToString};

use ebpf_command::command::{AttachProgram, DetachProgram};
use hermit_sync::{Lazy, SpinMutex};

use crate::ebpf::GLOBAL_EBPF_PROGS;
use crate::ebpf::command::eBPFCommandExec;
use crate::tracepoint::{TracepointPerfEvent, trace_point_manager};

static TP_EVENTS: Lazy<SpinMutex<BTreeMap<u32, TracepointPerfEvent>>> =
	Lazy::new(|| SpinMutex::new(BTreeMap::new()));

static ATTACH: Lazy<SpinMutex<BTreeMap<u64, u32>>> = Lazy::new(|| SpinMutex::new(BTreeMap::new()));

impl eBPFCommandExec for AttachProgram<'_> {
	fn execute(self) -> Result<String, String> {
		let programs = GLOBAL_EBPF_PROGS.lock();
		if let Some(program) = programs.get(self.name) {
			let mut tp_events = TP_EVENTS.lock();
			let tp_event = tp_events.get(&self.tracepoint_id);
			let bind_id = if let Some(tp_event) = tp_event {
				tp_event.bind_ebpf(program.get_new_insn().clone()).unwrap()
			} else {
				// create a new TracepointPerfEvent
				let manager = trace_point_manager();
				let tp_map = manager.tracepoint_map();
				let tp = tp_map
					.get(&self.tracepoint_id)
					.ok_or_else(|| "Tracepoint not found".to_string())?;
				let tp_event = TracepointPerfEvent::new(tp);
				let bind_id = tp_event.bind_ebpf(program.get_new_insn().clone()).unwrap();
				tp_events.insert(self.tracepoint_id, tp_event);
				bind_id
			};
			ATTACH.lock().insert(bind_id, self.tracepoint_id);
			Ok(bind_id.to_string())
		} else {
			Err("Program not found".to_string())
		}
	}
}

impl eBPFCommandExec for DetachProgram {
	fn execute(self) -> Result<String, String> {
		let mut attach = ATTACH.lock();
		if let Some(tp_id) = attach.remove(&self.0) {
			let mut tp_events = TP_EVENTS.lock();
			if let Some(tp_event) = tp_events.get_mut(&tp_id) {
				tp_event
					.unbind_ebpf(self.0)
					.expect("Failed to unbind eBPF program");
				if tp_event.ebpf_progs_len() == 0 {
					tp_events.remove(&tp_id);
				}
				Ok("".to_string())
			} else {
				Err("Tracepoint event not found".to_string())
			}
		} else {
			Err("Attach entry not found".to_string())
		}
	}
}
