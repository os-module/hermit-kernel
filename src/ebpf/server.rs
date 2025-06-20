/// eBPF server loop
#[cfg(feature = "udp")]
pub fn ebpf_server() {
	use ebpf_command::command::eBPFCommandParser;

	use crate::ebpf::command::eBPFCommandExec;
	use crate::syscalls::socket::{
		AF_INET, SockType, in_addr, sockaddr, sockaddr_in, sys_bind, sys_recvfrom, sys_sendto,
		sys_socket,
	};
	use crate::syscalls::sys_yield;

	let fd = sys_socket(AF_INET, SockType::SOCK_DGRAM, 0);
	assert!((fd >= 0), "Failed to create eBPF socket: {fd}");

	log::trace!("eBPF server started with socket fd: {fd}");

	let ip_u32 = u32::from_ne_bytes([0, 0, 0, 0]);

	let sockaddr = sockaddr_in {
		sin_len: core::mem::size_of::<sockaddr>() as _,
		sin_family: AF_INET as _,
		sin_port: 9970u16.to_be(), // Port in network byte order
		sin_addr: in_addr { s_addr: ip_u32 },
		sin_zero: [0; 8], // Padding
	};

	let res = unsafe {
		sys_bind(
			fd,
			(&raw const sockaddr)
				.cast::<sockaddr_in>()
				.cast::<sockaddr>(),
			core::mem::size_of::<sockaddr_in>() as _,
		)
	};
	assert!(
		res >= 0,
		"Failed to bind eBPF socket to address 0.0.0.0:9970: {res}"
	);

	log::info!("eBPF server bound to address: 0.0.0.0:9970");

	let mut buf = [0u8; 1024];

	let mut client_socket_addr = sockaddr::default();
	let mut client_socket_addr_len = core::mem::size_of::<sockaddr>() as u32;
	// receive and process user messages
	loop {
		let len = unsafe {
			sys_recvfrom(
				fd,
				buf.as_mut_ptr(),
				buf.len(),
				0,
				&raw mut client_socket_addr,
				&raw mut client_socket_addr_len,
			)
		};
		if len < 0 {
			log::trace!("Error receiving data: {len}");
			continue;
		}
		if len == 0 {
			sys_yield();
			continue; // No data received, yield to avoid busy waiting
		}
		// Process the received data (e.g., parse eBPF commands)
		// For now, just print the received data
		// log::trace!("Received {len} bytes: {:x?}", &buf[..len as usize]);

		let command = eBPFCommandParser::parse(&buf[..len as usize]);
		match command {
			Ok(cmd) => {
				log::trace!("Parsed eBPF command: {cmd:?}");
				let res = cmd.execute();
				match res {
					Ok(info) => {
						log::trace!(
							"eBPF command executed successfully, result length: {}",
							info.len()
						);
						unsafe {
							sys_sendto(
								fd,
								info.as_ptr(),
								info.len(),
								0,
								&raw const client_socket_addr,
								client_socket_addr_len,
							);
						}
					}
					Err(e) => {
						log::error!("Failed to execute eBPF command: {e}");
						unsafe {
							sys_sendto(
								fd,
								e.as_ptr(),
								e.len(),
								0,
								&raw const client_socket_addr,
								client_socket_addr_len,
							)
						};
					}
				}
			}
			Err(e) => {
				log::error!("Failed to parse eBPF command: {e:?}");
			}
		}
	}
}
