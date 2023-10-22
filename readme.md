
---
# NetCage: User-Level Network Access Controller


## TODO:
- [ ] Add a `--verbose` option
- [X] Track all child processes
- [X] Support IPv6
- [ ] Support more network system calls
- [ ] Support add rule in arguments
- [ ] Support non-standard IPV6 address
- [ ] Support Listening
- [ ] Support domain names
- [ ] Support port filter
- [ ] Support wildcard

**Version:** 1.1.0  
**License:** MIT

---

## Description

NetCage is a user-level network access control tool designed to provide network access restrictions for processes, particularly in environments where you don't have root access or are in incompatible containers. Unlike traditional methods such as iptables or firewalls, NetCage offers an alternative approach through Ptrace to ensure your processes remain within defined network parameters.

---

## Features

- **User-level Control:** No root access required.
- **Container-friendly:** Works seamlessly in a variety of container environments.
- **Lightweight:** Minimal resource overhead.
- **Custom Rules:** Define specific network access rules per process.

---

## Build

```bash
git clone https://github.com/YourUsername/NetGuardian.git
cd NetGuardian
cargo build
```

---

## Usage

1. **Basic Usage:**

    ```bash
    netcage -p [PROFILE] [COMMAND]
    ```

[//]: # (2. )

[//]: # (    ```bash)

[//]: # (    )
[//]: # (    ```)

For more detailed usage instructions, please refer to the [User Guide](docs/GUIDE.md).

---

## Contributing

We welcome contributions! Please check out our [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

---

## Support & Feedback

For support or to provide feedback, please raise an issue on our [GitHub repository](https://github.com/YourUsername/NetGuardian).

---

## License

NetCage is released under the [MIT License](link-to-license-file.md).

---

## Acknowledgments

Special thanks to the community and everyone who contributed to making this project possible.

---

## Changelog
- **1.1.0:** Added support for IPv6 and tracking child processes.

- **1.0.0:** Initial release.

For a detailed changelog, refer to the [CHANGELOG.md](docs/CHANGELOG.md).

---
