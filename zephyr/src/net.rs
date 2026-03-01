// Copyright (c) 2024 Linaro LTD
// SPDX-License-Identifier: Apache-2.0

//! # Zephyr networking support
//!
//! This module provides Rust-friendly wrappers around Zephyr's BSD socket API.

use core::ffi::{c_int, c_void};

use crate::error::{to_result, to_result_void, Result};
use crate::raw;

/// Address family (domain) for sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// IPv4 Internet protocols (AF_INET)
    IPV4 = raw::ZR_AF_INET as isize,
    /// IPv6 Internet protocols (AF_INET6)
    IPV6 = raw::ZR_AF_INET6 as isize,
}

/// Socket type.
///
/// This follows the naming convention from the socket2 crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    /// Stream socket (TCP)
    STREAM = raw::ZR_SOCK_STREAM as isize,
    /// Datagram socket (UDP)
    DGRAM = raw::ZR_SOCK_DGRAM as isize,
}

/// Protocol for sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// TCP protocol
    TCP = raw::ZR_IPPROTO_TCP as isize,
    /// UDP protocol
    UDP = raw::ZR_IPPROTO_UDP as isize,
}

/// A wrapper around a Zephyr socket file descriptor.
///
/// This provides a safe Rust interface to Zephyr's BSD socket API.
/// The socket is automatically closed when dropped.
pub struct Socket {
    fd: c_int,
}

impl Socket {
    /// Creates a new socket.
    ///
    /// This API follows the socket2 crate convention.
    ///
    /// # Arguments
    ///
    /// * `domain` - The address domain (e.g., IPv4 or IPv6)
    /// * `type_` - The socket type (e.g., Stream or Dgram)
    /// * `protocol` - Optional protocol. If None, uses the default protocol for the given domain and type.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use zephyr::net::{Socket, Domain, Type, Protocol};
    ///
    /// // Create a TCP socket
    /// let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    ///
    /// // Create a UDP socket with default protocol
    /// let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
    /// ```
    pub fn new(domain: Domain, type_: Type, protocol: Option<Protocol>) -> Result<Self> {
        let protocol_value = protocol.map(|p| p as c_int).unwrap_or(0);

        let fd = unsafe { raw::zr_socket(domain as c_int, type_ as c_int, protocol_value) };

        to_result(fd).map(|fd| Socket { fd })
    }

    /// Binds the socket to a local address.
    ///
    /// This follows the socket2 crate convention.
    ///
    /// # Arguments
    ///
    /// * `addr` - The socket address to bind to
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use zephyr::net::{Socket, Domain, Type};
    /// use core::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
    ///
    /// let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
    /// let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 8888));
    /// socket.bind(&addr)?;
    /// ```
    pub fn bind(&self, addr: &core::net::SocketAddr) -> Result<()> {
        match addr {
            core::net::SocketAddr::V4(addr_v4) => {
                #[repr(C)]
                struct sockaddr_in {
                    sin_family: u16,
                    sin_port: u16,
                    sin_addr: u32,
                    sin_zero: [u8; 8],
                }
                let sockaddr_in = sockaddr_in {
                    sin_family: Domain::IPV4 as u16,
                    sin_port: htons(addr_v4.port()),
                    sin_addr: htonl(u32::from_be_bytes(addr_v4.ip().octets())),
                    sin_zero: [0; 8],
                };
                unsafe {
                    let ret = raw::zr_bind(
                        self.fd,
                        &sockaddr_in as *const _ as *const _,
                        core::mem::size_of::<sockaddr_in>() as raw::net_socklen_t,
                    );
                    to_result_void(ret)
                }
            }
            core::net::SocketAddr::V6(_) => {
                // IPv6 is not yet supported
                Err(crate::error::Error(raw::EAFNOSUPPORT))
            }
        }
    }

    /// Receives data from a socket and returns the source address.
    ///
    /// This follows the socket2 crate convention.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to store the received data
    ///
    /// # Returns
    ///
    /// Returns a tuple of (number of bytes received, source address).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use zephyr::net::{Socket, Domain, Type};
    ///
    /// let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
    /// let mut buffer = [0u8; 256];
    /// let (recv_len, src_addr) = socket.recv_from(&mut buffer)?;
    /// ```
    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, core::net::SocketAddr)> {
        #[repr(C)]
        struct sockaddr_in {
            sin_family: u16,
            sin_port: u16,
            sin_addr: u32,
            sin_zero: [u8; 8],
        }
        let mut sockaddr_in = sockaddr_in {
            sin_family: 0,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0; 8],
        };
        let mut addrlen = core::mem::size_of::<sockaddr_in>() as raw::net_socklen_t;

        unsafe {
            let result = raw::zr_recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0, // flags = 0 (default behavior)
                &mut sockaddr_in as *mut _ as *mut _,
                &mut addrlen,
            );

            to_result(result as c_int).map(|_| {
                // Convert sockaddr_in to core::net::SocketAddr
                let port = u16::from_be(sockaddr_in.sin_port);
                let addr_bytes = u32::from_be(sockaddr_in.sin_addr).to_be_bytes();
                let ipv4_addr = core::net::Ipv4Addr::from(addr_bytes);
                let socket_addr =
                    core::net::SocketAddr::V4(core::net::SocketAddrV4::new(ipv4_addr, port));

                (result as usize, socket_addr)
            })
        }
    }

    /// Returns the raw file descriptor for this socket.
    ///
    /// This can be used for interoperability with C code or other low-level operations.
    pub fn as_raw_fd(&self) -> c_int {
        self.fd
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe {
            raw::zr_close(self.fd);
        }
    }
}

/// IPv4 socket address constant - bind to any address
pub const INADDR_ANY: u32 = 0;

/// Helper function to convert u16 to network byte order (big-endian)
#[inline]
pub fn htons(hostshort: u16) -> u16 {
    hostshort.to_be()
}

/// Helper function to convert u32 to network byte order (big-endian)
#[inline]
pub fn htonl(hostlong: u32) -> u32 {
    hostlong.to_be()
}

