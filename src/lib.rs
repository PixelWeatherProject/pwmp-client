use consts::{
    CONNECT_TIMEOUT, NOTIFICATION_MAX_LEN, RCV_BUFFER_SIZE, READ_TIMEOUT, UPDATE_PART_SIZE,
    WRITE_TIMEOUT,
};
use error::Error;
pub use pwmp_msg;
use pwmp_msg::{
    aliases::{AirPressure, Humidity, Rssi},
    mac::Mac,
    request::Request,
    response::Response,
    settings::NodeSettings,
    version::Version,
    Message, MsgId,
};
use std::{
    io::{self, IoSlice, Read, Write},
    net::{Shutdown, TcpStream, ToSocketAddrs},
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

    /// IDs of previously received message.
    prev_id: Option<MsgId>,

    /// A function capable of generating a new message ID.
    ///
    /// This may be a random number generator, or something else.
    ///
    /// # Note
    /// The uniqueness of every returned ID must be guarateed by the generator
    /// itself. If the function returns the same ID twice in a row, the server
    /// will reject the message, due to the duplicate ID.
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

        socket.set_nodelay(true)?;
        socket.set_read_timeout(Some(read_timeout.unwrap_or(READ_TIMEOUT)))?;
        socket.set_write_timeout(Some(write_timeout.unwrap_or(WRITE_TIMEOUT)))?;

        Ok(Self {
            stream: socket,
            buffer: [0; RCV_BUFFER_SIZE],
            prev_id: None,
            id_generator,
        })
    }

    /// Send a handshake request.
    ///
    /// # Errors
    /// Generic I/O.
    pub fn initialize_session(
        &mut self,
        mac: Mac,
        os_version: Version,
        os_version_ext: Option<Box<str>>,
    ) -> Result<()> {
        self.send_request(Request::Hello {
            mac,
            os_version,
            os_version_ext,
        })?;
        self.wait_for_ok()
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
    #[allow(clippy::too_many_arguments)]
    pub fn post_measurements(
        &mut self,
        temperature: f32,
        humidity: Humidity,
        air_pressure: Option<AirPressure>,
        battery: f32,
        cpu_temp: f32,
        wifi_ssid: &str,
        wifi_rssi: Rssi,
    ) -> Result<()> {
        self.send_request(Request::PostMeasurements {
            temperature: celsius_to_decicelsius(temperature)?,
            humidity,
            air_pressure,
            battery: volts_to_millivolts(battery)?,
            cpu_temp: celsius_to_decicelsius(cpu_temp)?,
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

        if message.len() >= NOTIFICATION_MAX_LEN {
            return Err(Error::IllegalNotificationLength(message.len()));
        }

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
    pub fn next_update_chunk(&mut self, chunk_size: Option<u32>) -> Result<Option<Box<[u8]>>> {
        let chunk_size = chunk_size.unwrap_or(UPDATE_PART_SIZE);
        self.send_request(Request::NextUpdateChunk(chunk_size))?;
        let chunk_size: usize = chunk_size.try_into()?;

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
        // Serialize the message.
        let raw = msg.serialize().map_err(Error::Serialize)?;

        // Get the length and store it as a proper length integer.
        let length: MsgLength = raw.len().try_into().map_err(|_| Error::MessageTooLarge)?;
        let header = length.to_be_bytes();

        // Prepare the complete message for a vectored write
        let mut slices = &mut [IoSlice::new(&header), IoSlice::new(&raw)][..];

        // Write the entire message to the stocket
        while !slices.is_empty() {
            let written = self.stream.write_vectored(slices)?;

            if written == 0 {
                return Err(io::Error::from(io::ErrorKind::WriteZero).into());
            }

            // Skip past whatever was written, in case the kernel accepted only part of it.
            IoSlice::advance_slices(&mut slices, written);
        }

        // Flush the buffer.
        self.stream.flush()?;

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
            MsgLength::from_be_bytes(buffer[..size_of::<MsgLength>()].try_into()?).try_into()?;

        // Verify the length
        if message_length == 0 {
            return Err(Error::IllegalMessageLength);
        }

        // Verify that the buffer is large enough.
        if buffer.len() < message_length {
            return Err(Error::InvalidBuffer);
        }

        // Read the actual message.
        self.stream.read_exact(&mut buffer[..message_length])?;

        // Parse the message.
        let message = Message::deserialize(&buffer[..message_length]).ok_or(Error::MessageParse)?;

        // Check if it's not a duplicate.
        if self.is_id_duplicate(message.id()) {
            return Err(Error::DuplicateMessage);
        }

        // Cache the ID.
        self.prev_id = Some(message.id());

        // Done
        Ok(message)
    }

    fn is_id_duplicate(&self, id: MsgId) -> bool {
        self.prev_id == Some(id)
    }
}

impl Drop for PwmpClient {
    fn drop(&mut self) {
        // Send the bye message.
        // If the socket is already dead this will fail, but we can ignore that.
        let _ = self.send_request(Request::Bye);

        // Shut down the socket
        let _ = self.stream.shutdown(Shutdown::Write);
    }
}

#[allow(clippy::cast_possible_truncation)]
fn celsius_to_decicelsius(c: f32) -> Result<i16> {
    let value = (c * 10.0).round();

    if !value.is_finite() || value < f32::from(i16::MIN) || value > f32::from(i16::MAX) {
        return Err(Error::IllegalValue(c));
    }

    Ok(value as i16)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn volts_to_millivolts(v: f32) -> Result<u16> {
    let value = (v * 1000.0).round();

    if !value.is_finite() || value < 0.0 || value > f32::from(u16::MAX) {
        return Err(Error::IllegalValue(v));
    }

    Ok(value as u16)
}
