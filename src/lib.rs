#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]
use arrayref::array_ref;
use consts::{
    CONNECT_TIMEOUT, ID_CACHE_SIZE, NOTIFICATION_MAX_LEN, RCV_BUFFER_SIZE, READ_TIMEOUT,
    UPDATE_PART_SIZE, WRITE_TIMEOUT,
};
use error::Error;
use libc::{linger, socklen_t, SOL_SOCKET, SO_KEEPALIVE, SO_LINGER};
pub use pwmp_msg;
use pwmp_msg::{
    aliases::{AirPressure, BatteryVoltage, Humidity, Rssi, Temperature},
    mac::Mac,
    request::Request,
    response::Response,
    settings::NodeSettings,
    version::Version,
    Message, MsgId,
};
use std::{
    ffi::c_int,
    io::{self, Read, Write},
    mem,
    net::{Shutdown, TcpStream, ToSocketAddrs},
    os::fd::AsRawFd,
    time::Duration,
};

pub(crate) type Result<T> = ::std::result::Result<T, Error>;
type MsgLength = u32;

/// Contains the [`Error`] type.
pub mod error;

/// Types for OTA updates.
pub mod ota;

/// Contains internal constants.
mod consts;

#[allow(clippy::doc_markdown)]
/// PixelWeather Messaging Protocol Client.
pub struct PwmpClient {
    /// Handle for the actual TCP stream.
    stream: TcpStream,

    /// Default buffer used to receive messages.
    buffer: [u8; RCV_BUFFER_SIZE],

    /// IDs of previously received messages.
    id_cache: [MsgId; ID_CACHE_SIZE],

    /// A function capable of generating a new message ID.
    ///
    /// This may be a random number generator, or something else.
    id_generator: &'static dyn Fn() -> MsgId,
}

impl PwmpClient {
    /// Create a new client by connecting to a PWMP server.
    ///
    /// # Errors
    /// If the server rejects the client (for eg. if it's unathorized)
    /// an `Err(Error::Reject)` is returned. An error is also returned
    /// if a generic I/O error occurred.
    pub fn new<A, G>(
        addr: A,
        id_generator: &'static G,
        connect_timeout: Option<Duration>,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
    ) -> Result<Self>
    where
        A: ToSocketAddrs,
        G: Fn() -> MsgId,
    {
        let addr = addr.to_socket_addrs()?.next().ok_or(Error::IllegalAddr)?;
        let socket = TcpStream::connect_timeout(&addr, connect_timeout.unwrap_or(CONNECT_TIMEOUT))?;

        // Set the options
        setsockopt(&socket, SOL_SOCKET, SO_KEEPALIVE, 1i32)?;
        setsockopt(
            &socket,
            SOL_SOCKET,
            SO_LINGER,
            Some(linger {
                l_linger: 5,
                l_onoff: 1,
            }),
        )?;
        socket.set_nodelay(true)?;
        socket.set_read_timeout(Some(read_timeout.unwrap_or(READ_TIMEOUT)))?;
        socket.set_write_timeout(Some(write_timeout.unwrap_or(WRITE_TIMEOUT)))?;

        Ok(Self {
            stream: socket,
            buffer: [0; RCV_BUFFER_SIZE],
            id_cache: Default::default(),
            id_generator,
        })
    }

    /// Try to ping the server. Returns whether the server responded correctly.
    /// On an I/O error, `false` is returned.
    pub fn ping(&mut self) -> bool {
        if self.send_request(Request::Ping).is_err() {
            return false;
        }

        let Ok(response) = self.receive_response(None) else {
            return false;
        };

        response == Response::Pong
    }

    /// Get the node's settings.
    ///
    /// # Errors
    /// Generic I/O.
    #[allow(clippy::items_after_statements)]
    pub fn get_settings(&mut self) -> Result<Option<NodeSettings>> {
        self.send_request(Request::GetSettings)?;
        let response = self.receive_response(None)?;

        let Response::Settings(values) = response else {
            return Err(Error::UnexpectedResponse {
                expected: "Settings",
                got: response,
            });
        };

        Ok(values)
    }

    /// Post node measurements.
    ///
    /// # Errors
    /// Generic I/O.
    pub fn post_measurements(
        &mut self,
        temperature: Temperature,
        humidity: Humidity,
        air_pressure: Option<AirPressure>,
    ) -> Result<()> {
        self.send_request(Request::PostResults {
            temperature,
            humidity,
            air_pressure,
        })?;
        self.wait_for_ok()
    }

    /// Post node stats.
    ///
    /// # Errors
    /// Generic I/O.
    pub fn post_stats(
        &mut self,
        battery: BatteryVoltage,
        wifi_ssid: &str,
        wifi_rssi: Rssi,
    ) -> Result<()> {
        self.send_request(Request::PostStats {
            battery,
            wifi_ssid: wifi_ssid.into(),
            wifi_rssi,
        })?;
        self.wait_for_ok()
    }

    /// Send a text notification with the specified content.
    ///
    /// # Errors
    /// Generic I/O.
    pub fn send_notification<S: Into<Box<str>>>(&mut self, content: S) -> Result<()> {
        // This should not allocate if `S` was a `String` *AND* it does *NOT* have excess capacity.
        let message: Box<str> = content.into();

        assert!(
            message.len() <= NOTIFICATION_MAX_LEN,
            "Message content too large"
        );
        self.send_request(Request::SendNotification(message))?;
        self.wait_for_ok()
    }

    /// Check if a newer firmware is available on the server.
    ///
    /// # Errors
    /// Generic I/O or if an unexpected response variant is received.
    pub fn check_os_update(&mut self, current_version: Version) -> Result<ota::UpdateStatus> {
        self.send_request(Request::UpdateCheck(current_version))?;

        match self.receive_response(None)? {
            Response::FirmwareUpToDate => Ok(ota::UpdateStatus::UpToDate),
            Response::UpdateAvailable(version) => Ok(ota::UpdateStatus::Available(version)),
            other => Err(Error::UnexpectedResponse {
                expected: "FirmwareUpToDate/UpdateAvailable",
                got: other,
            }),
        }
    }

    /// Request the next chunk of a firmware update.
    /// Optionally, a chunk size can be specified. This will be the *maximum* length of the received chunk.
    ///
    /// # Defaults
    /// If no chunk size is specified, a default value will be used. Check [`UPDATE_PART_SIZE`](UPDATE_PART_SIZE)
    ///
    /// # Errors
    /// Generic I/O
    pub fn next_update_chunk(&mut self, chunk_size: Option<usize>) -> Result<Option<Box<[u8]>>> {
        let chunk_size = chunk_size.unwrap_or(UPDATE_PART_SIZE);
        self.send_request(Request::NextUpdateChunk(chunk_size))?;

        let mut buffer = vec![0; chunk_size + 32 /* Message overhead */];
        let response = self.receive_response(Some(&mut buffer))?;

        match response {
            Response::UpdatePart(chunk) => Ok(Some(chunk)),
            Response::UpdateEnd => Ok(None),
            _ => Err(Error::UnexpectedResponse {
                expected: "UpdatePart/UpdateEnd",
                got: response,
            }),
        }
    }

    /// Report the last firmware update as either successfull, or failed due to malfunctioning firmware.
    /// If a firmware is reported as "bad", it'll be blacklisted for the current node.
    ///
    /// # Errors
    /// Generic I/O
    pub fn report_firmware(&mut self, ok: bool) -> Result<()> {
        self.send_request(Request::ReportFirmwareUpdate(ok))?;
        self.wait_for_ok()
    }

    /// Send a handshake request.
    ///
    /// # Errors
    /// Generic I/O.
    pub fn perform_handshake(&mut self, mac: Mac) -> Result<()> {
        self.send_request(Request::Handshake { mac })?;
        self.wait_for_ok()
    }

    /// Wait for the server to reply with an `Ok` message.
    ///
    /// # Errors
    /// Generic I/O.
    fn wait_for_ok(&mut self) -> Result<()> {
        // Read the next message.
        let response = self.receive_response(None)?;

        // Check if it's an OK.
        if !matches!(response, Response::Ok) {
            return Err(Error::UnexpectedResponse {
                expected: "Ok",
                got: response,
            });
        }

        Ok(())
    }

    fn send_request(&mut self, req: Request) -> Result<()> {
        self.send_message(Message::new_request(req, (self.id_generator)()))
    }

    fn send_message(&mut self, msg: Message) -> Result<()> {
        // Make a copy of the message ID to use later.
        // The message object will be moved, and we don't want to store an ID
        // that's never been actually sent.
        let id = msg.id();

        // Serialize the message.
        let raw = msg.serialize();

        // Get the length and store it as a proper length integer.
        let length: MsgLength = raw.len().try_into().map_err(|_| Error::MessageTooLarge)?;

        // Send the length first as big/network endian.
        self.stream.write_all(length.to_be_bytes().as_slice())?;

        // Send the actual message next.
        // TODO: Endianness should be handled internally, but this should be checked!
        self.stream.write_all(&raw)?;

        // Flush the buffer.
        self.stream.flush()?;

        // Cache the ID.
        self.cache_id(id);

        // Done
        Ok(())
    }

    fn receive_response(&mut self, buffer: Option<&mut [u8]>) -> Result<Response> {
        // Receive the message.
        let message = self.receive_message(buffer)?;

        // Convert it to a response.
        let response = message.take_response().ok_or(Error::NotResponse)?;

        // Check if the server returned an error.
        Error::check_server_error(response)
    }

    fn receive_message(&mut self, buffer: Option<&mut [u8]>) -> Result<Message> {
        // Use the provided buffer, or provide a default one.
        let buffer = buffer.unwrap_or(&mut self.buffer);

        // First read the message size.
        self.stream
            .read_exact(&mut buffer[..size_of::<MsgLength>()])?;

        // Parse the length
        let message_length: usize =
            u32::from_be_bytes(*array_ref![buffer, 0, size_of::<u32>()]).try_into()?;

        // Verify the length
        if message_length == 0 {
            return Err(Error::IllegalMessageLength);
        }
        // TODO: Add more restrictions as needed...

        // Verify that the buffer is large enough.
        if buffer.len() < message_length {
            return Err(Error::InvalidBuffer);
        }

        // Read the actual message.
        self.stream.read_exact(&mut buffer[..message_length])?;

        // Parse the message.
        let message = Message::deserialize(buffer).ok_or(Error::MessageParse)?;

        // Check if it's not a duplicate.
        if self.is_id_cached(message.id()) {
            return Err(Error::DuplicateMessage);
        }

        // Cache the ID.
        self.cache_id(message.id());

        // Done
        Ok(message)
    }

    fn is_id_cached(&self, id: MsgId) -> bool {
        // Check if the ID matches any of the cached ones.
        self.id_cache.iter().any(|candidate| candidate == &id)
    }

    fn cache_id(&mut self, id: MsgId) {
        // Rotate the array left by one.
        self.id_cache.rotate_left(1);

        // Set the last ID to the specified one.
        self.id_cache[self.id_cache.len() - 1] = id;
    }
}

impl Drop for PwmpClient {
    fn drop(&mut self) {
        // Send the bye message.
        // If the socket is already dead this will fail, but we can ignore that.
        let _ = self.send_request(Request::Bye);

        // Shut down the socket
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

fn setsockopt<T, FD: AsRawFd>(fd: &FD, level: c_int, opt: c_int, value: T) -> io::Result<()> {
    let (ptr, len) = (&value as *const T as *const _, mem::size_of::<T>());
    let err = unsafe { libc::setsockopt(fd.as_raw_fd(), level, opt, ptr, len as socklen_t) };

    if err == 0 {
        return Ok(());
    }

    Err(io::Error::last_os_error())
}
