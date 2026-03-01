// Copyright (c) 2024 Linaro LTD
// SPDX-License-Identifier: Apache-2.0

//! # Zephyr networking support
//!
//! This module provides Rust-friendly wrappers around Zephyr's BSD socket API.

use core::ffi::c_int;

use crate::error::{to_result, to_result_void, Result};
use crate::raw;

/// Address family for sockets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// IPv4 Internet protocols
    Inet = raw::ZR_AF_INET as isize,
    /// IPv6 Internet protocols
    Inet6 = raw::ZR_AF_INET6 as isize,
}

/// Socket type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    /// Stream socket (TCP)
    Stream = raw::ZR_SOCK_STREAM as isize,
    /// Datagram socket (UDP)
    Dgram = raw::ZR_SOCK_DGRAM as isize,
}

/// Protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// TCP protocol
    Tcp = raw::ZR_IPPROTO_TCP as isize,
    /// UDP protocol
    Udp = raw::ZR_IPPROTO_UDP as isize,
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
    /// # Arguments
    ///
    /// * `family` - The address family (e.g., IPv4 or IPv6)
    /// * `socket_type` - The socket type (e.g., Stream or Dgram)
    /// * `protocol` - The protocol to use
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use zephyr::net::{Socket, AddressFamily, SocketType, Protocol};
    ///
    /// let socket = Socket::new(
    ///     AddressFamily::Inet,
    ///     SocketType::Stream,
    ///     Protocol::Tcp
    /// )?;
    /// ```
    pub fn new(family: AddressFamily, socket_type: SocketType, protocol: Protocol) -> Result<Self> {
        let fd = unsafe {
            raw::zr_socket(
                family as c_int,
                socket_type as c_int,
                protocol as c_int,
            )
        };

        to_result(fd).map(|fd| Socket { fd })
    }

    /// Binds the socket to a local address.
    ///
    /// # Arguments
    ///
    /// * `addr` - Pointer to the socket address structure
    /// * `addrlen` - Length of the address structure
    ///
    /// # Safety
    ///
    /// The caller must ensure that `addr` points to a valid socket address structure
    /// of the appropriate type for the socket's address family, and that `addrlen`
    /// correctly represents the size of that structure.
    pub unsafe fn bind(&self, addr: *const raw::net_sockaddr, addrlen: raw::net_socklen_t) -> Result<()> {
        let ret = raw::zr_bind(self.fd, addr as *const _, addrlen);
        to_result_void(ret)
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
