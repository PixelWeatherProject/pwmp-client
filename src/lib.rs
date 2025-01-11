#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]
use consts::{
    CONNECT_TIMEOUT, NOTIFICATION_MAX_LEN, RCV_BUFFER_SIZE, READ_TIMEOUT, UPDATE_PART_SIZE,
    WRITE_TIMEOUT,
};
use error::Error;
pub use pwmp_msg;
use pwmp_msg::{
    aliases::{AirPressure, BatteryVoltage, Humidity, Rssi, Temperature},
    mac::Mac,
    request::Request,
    response::Response,
    settings::NodeSettings,
    version::Version,
    Message,
};
use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

pub(crate) type Result<T> = ::std::result::Result<T, Error>;

/// Contains the [`Error`] type.
pub mod error;

/// Types for OTA updates.
pub mod ota;

/// Contains internal constants.
mod consts;

#[allow(clippy::doc_markdown)]
/// PixelWeather Messaging Protocol Client.
pub struct PwmpClient {
    stream: TcpStream,
    buffer: [u8; RCV_BUFFER_SIZE],
}

impl PwmpClient {
    /// Create a new client by connecting to a PWMP server.
    ///
    /// # Errors
    /// If the server rejects the client (for eg. if it's unathorized)
    /// an `Err(Error::Reject)` is returned. An error is also returned
    /// if a generic I/O error occurred.
    pub fn new<A: ToSocketAddrs>(
        addr: A,
        mac: Mac,
        connect_timeout: Option<Duration>,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
    ) -> Result<Self> {
        let addr = addr.to_socket_addrs()?.next().unwrap();
        let socket = TcpStream::connect_timeout(&addr, connect_timeout.unwrap_or(CONNECT_TIMEOUT))?;

        socket.set_read_timeout(Some(read_timeout.unwrap_or(READ_TIMEOUT)))?;
        socket.set_write_timeout(Some(write_timeout.unwrap_or(WRITE_TIMEOUT)))?;

        let mut client = Self {
            stream: socket,
            buffer: [0; RCV_BUFFER_SIZE],
        };
        client.send_greeting(mac)?;

        Ok(client)
    }

    /// Try to ping the server. Returns whether the server responded correctly.
    /// On an I/O error, `false` is returned.
    pub fn ping(&mut self) -> bool {
        if self.send_request(Request::Ping).is_err() {
            return false;
        }

        let Ok(response) = self.await_response(None) else {
            return false;
        };

        response == Response::Pong
    }

    /// Get the node's settings.
    ///
    /// # Errors
    /// Generic I/O.
    #[allow(clippy::items_after_statements)]
    pub fn get_settings(&mut self) -> Result<NodeSettings> {
        self.send_request(Request::GetSettings)?;
        let response = self.await_response(None)?;

        let Response::Settings(values) = response else {
            return Err(Error::UnexpectedVariant);
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
        self.await_ok()
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
        self.await_ok()
    }

    /// Send a text notification with the specified content.
    ///
    /// # Errors
    /// Generic I/O.
    pub fn send_notification(&mut self, content: &str) -> Result<()> {
        assert!(
            content.len() <= NOTIFICATION_MAX_LEN,
            "Message content too large"
        );
        self.send_request(Request::SendNotification(content.into()))?;
        self.await_ok()
    }

    /// Check if a newer firmware is available on the server.
    ///
    /// # Errors
    /// Generic I/O or if an unexpected response variant is received.
    pub fn check_os_update(&mut self, current_version: Version) -> Result<ota::UpdateStatus> {
        self.send_request(Request::UpdateCheck(current_version))?;

        match self.await_response(None)? {
            Response::FirmwareUpToDate => Ok(ota::UpdateStatus::UpToDate),
            Response::UpdateAvailable(version) => Ok(ota::UpdateStatus::Available(version)),
            _ => Err(Error::UnexpectedVariant),
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
        let response = self.await_response(Some(&mut buffer))?;

        match response {
            Response::UpdatePart(chunk) => Ok(Some(chunk)),
            Response::UpdateEnd => Ok(None),
            _ => Err(Error::UnexpectedVariant),
        }
    }

    /// Report the last firmware update as either successfull, or failed due to malfunctioning firmware.
    /// If a firmware is reported as "bad", it'll be blacklisted for the current node.
    ///
    /// # Errors
    /// Generic I/O
    pub fn report_firmware(&mut self, ok: bool) -> Result<()> {
        self.send_request(Request::ReportFirmwareUpdate(ok))?;
        self.await_ok()
    }

    /// Send the initial greeting message to the server.
    ///
    /// # Errors
    /// Generic I/O.
    fn send_greeting(&mut self, mac: Mac) -> Result<()> {
        self.send_request(Request::Hello { mac })?;
        self.await_ok()
    }

    /// Send a request to the server.
    ///
    /// # Errors
    /// Generic I/O.
    fn send_request(&mut self, req: Request) -> Result<()> {
        self.stream.write_all(&Message::Request(req).serialize())?;
        self.stream.flush()?;

        Ok(())
    }

    /// Wait for a response from the server.
    ///
    /// # Errors
    /// Generic I/O.
    fn await_response(&mut self, buffer: Option<&mut [u8]>) -> Result<Response> {
        let buffer = buffer.unwrap_or_else(|| {
            self.buffer.fill(0);
            &mut self.buffer
        });
        let read = self.stream.read(buffer)?;

        let message = Message::deserialize(&buffer[..read]).ok_or(Error::MessageParse)?;
        message.as_response().ok_or(Error::NotResponse)
    }

    /// Wait for the server to reply with an `Ok` message.
    ///
    /// # Errors
    /// Generic I/O.
    fn await_ok(&mut self) -> Result<()> {
        let response = self.await_response(None)?;

        match response {
            Response::Ok => Ok(()),
            Response::Reject => Err(Error::Rejected),
            _ => Err(Error::NotResponse),
        }
    }

    /// Check if the client has a connection to the server.
    ///
    /// # Errors
    /// Generic I/O.
    fn connected(&self) -> bool {
        if let Ok(amount) = self.stream.peek(&mut []) {
            return amount > 0;
        }

        false
    }
}

impl Drop for PwmpClient {
    fn drop(&mut self) {
        // Send the bye message
        let _ = self.send_request(Request::Bye);

        // Wait until we disconnect
        while self.connected() {}
    }
}
