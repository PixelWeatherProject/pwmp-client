# PWMP Client library
This crate contains the library used by nodes to connect to and communicate with the [PixelWeather Messaging Protocol server](https://github.com/PixelWeatherProject/pwmp-server).

See other repositories for more components of the PixelWeather ecosystem:
- [Core types of the messaging protocol (`pwmp-msg`)](https://github.com/PixelWeatherProject/pwmp-msg)
- [Server implementation (`pwmp-server`)](https://github.com/PixelWeatherProject/pwmp-server)
- [Node firmware (`pwos`)](https://github.com/PixelWeatherProject/pwos)

# Example usage
Check [examples](examples/).

The library exports the [pwmp-msg](https://github.com/PixelWeatherProject/pwmp-msg) crate, so you don't need to include it separately in your `Cargo.toml`.

Further documentation can be generated using `cargo doc`.

# Platform restrictions
This library requires `std` and is **not** `no_std` compatible, and likely never be due to TCP sockets being used.

Due to the custom socket optimizations, this library requires linking to `libc` and is only compatible with Unix-like operating systems.