# PWMP Client library
This crate contains the library used by nodes to connect to and communicate with the [PixelWeather Messaging Protocol server](https://github.com/PixelWeatherProject/pwmp-server).

# Example usage
Check [examples](examples/).

The library exports the [pwmp-msg](https://github.com/PixelWeatherProject/pwmp-msg) crate, so you don't need to include it separately in your `Cargo.toml`.

Further documentation can be generated using `cargo doc`.

# Platform restrictions
This library requires `std` and is **not** `no_std` compatible, and likely never be due to TCP sockets being used.

Due to the custom socket optimizations, this library links to `libc` and is only compatible with Unix-like operating systems.