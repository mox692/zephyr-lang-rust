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
    pub unsafe fn bind(
        &self,
        addr: *const raw::net_sockaddr,
        addrlen: raw::net_socklen_t,
    ) -> Result<()> {
        let ret = raw::zr_bind(self.fd, addr as *const _, addrlen);
        to_result_void(ret)
    }

    /// Binds the socket to an IPv4 address.
    ///
    /// This is a safe wrapper around `bind` for IPv4 addresses.
    ///
    /// # Arguments
    ///
    /// * `addr` - The IPv4 socket address to bind to
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use zephyr::net::{Socket, Domain, Type, SockaddrIn, INADDR_ANY};
    ///
    /// let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
    /// let addr = SockaddrIn::new(8888, INADDR_ANY);
    /// socket.bind_v4(&addr)?;
    /// ```
    pub fn bind_v4(&self, addr: &SockaddrIn) -> Result<()> {
        unsafe { self.bind(addr.as_ptr(), SockaddrIn::len()) }
    }

    /// Receives data from a socket and stores the source address.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to store the received data
    /// * `flags` - Flags for the receive operation (typically 0)
    /// * `src_addr` - Optional mutable reference to store the source address
    ///
    /// # Returns
    ///
    /// Returns the number of bytes received on success.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use zephyr::net::{Socket, Domain, Type, SockaddrIn};
    ///
    /// let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
    /// let mut buffer = [0u8; 256];
    /// let mut src_addr = SockaddrIn::new(0, 0);
    /// let recv_len = socket.recvfrom(&mut buffer, 0, Some(&mut src_addr))?;
    /// ```
    pub fn recvfrom(
        &self,
        buf: &mut [u8],
        flags: c_int,
        src_addr: Option<&mut SockaddrIn>,
    ) -> Result<usize> {
        unsafe {
            let result = if let Some(addr) = src_addr {
                let mut addrlen = SockaddrIn::len();
                raw::zr_recvfrom(
                    self.fd,
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len(),
                    flags,
                    addr.as_mut_ptr(),
                    &mut addrlen,
                )
            } else {
                raw::zr_recvfrom(
                    self.fd,
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len(),
                    flags,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            };
            to_result(result as c_int).map(|_| result as usize)
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

/// IPv4 socket address structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockaddrIn {
    /// Address family (should be AF_INET)
    pub sin_family: u16,
    /// Port number in network byte order
    pub sin_port: u16,
    /// IPv4 address in network byte order
    pub sin_addr: u32,
    /// Padding to match C struct size
    pub sin_zero: [u8; 8],
}

impl SockaddrIn {
    /// Creates a new IPv4 socket address
    ///
    /// # Arguments
    ///
    /// * `port` - Port number in host byte order (will be converted to network byte order)
    /// * `addr` - IPv4 address in host byte order (will be converted to network byte order)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use zephyr::net::{SockaddrIn, INADDR_ANY};
    ///
    /// // Bind to any address on port 8888
    /// let addr = SockaddrIn::new(8888, INADDR_ANY);
    /// ```
    pub fn new(port: u16, addr: u32) -> Self {
        Self {
            sin_family: Domain::IPV4 as u16,
            sin_port: htons(port),
            sin_addr: htonl(addr),
            sin_zero: [0; 8],
        }
    }

    /// Returns a pointer to this structure suitable for passing to C functions
    pub fn as_ptr(&self) -> *const raw::net_sockaddr {
        self as *const Self as *const raw::net_sockaddr
    }

    /// Returns a mutable pointer to this structure suitable for passing to C functions
    pub fn as_mut_ptr(&mut self) -> *mut raw::net_sockaddr {
        self as *mut Self as *mut raw::net_sockaddr
    }

    /// Returns the size of this structure
    pub fn len() -> raw::net_socklen_t {
        core::mem::size_of::<Self>() as raw::net_socklen_t
    }
}
