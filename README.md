# AuthX Velocity

![Platform](https://img.shields.io/badge/Platform-Velocity-00b4ff)
![Java](https://img.shields.io/badge/Java-17%2B-red)
[![Modrinth](https://img.shields.io/badge/Modrinth-AuthX%20Velocity-1bd96a?logo=modrinth&logoColor=white)](https://modrinth.com/plugin/authx-velocity)
[![GitHub stars](https://img.shields.io/github/stars/MinecraftServerUnion/AuthX?style=flat&logo=github)](https://github.com/MinecraftServerUnion/AuthX/stargazers)

**AuthX Velocity** is an original authentication plugin for **Velocity** that provides a plug-and-play hybrid login experience for Minecraft Java servers.

It combines the core ideas of MultiLogin-style account routing and LimboAuth-style secure verification into one workflow, so you can support offline users and premium/Yggdrasil users at the same time with minimal setup.

## Basic information

- **Dependency:** LimboAPI ([Modrinth](https://modrinth.com/plugin/limboapi))
- **Velocity Support:** Velocity 3.4.0 - 3.5.0

## Why AuthX

AuthX is designed for mixed communities where players may join from:

- Offline mode launchers
- Mojang/Microsoft premium accounts
- Yggdrasil-compatible skin/auth providers (such as LittleSkin)

Instead of splitting your authentication stack into multiple plugins, AuthX gives you one consistent flow.

## Key Features

- **Hybrid authentication**
  Intelligently distinguishes and supports both password-based login (offline users) and fast Yggdrasil login (premium/skin-station users).

- **Secure limbo verification world**
  Built on **LimboAPI** to isolate unauthenticated players without occupying extra backend server resources.

- **User-friendly flow**
  Clear in-game prompts guide players through login/registration. No command learning required.

- **Flexible backend modes**
  Supports local password backends and UniAuth integration, with migration and UUID tooling for real-world deployments.

- **Modern account behavior**
  Includes method binding control, password change management, and UUID auto-assignment options for new users.

## Installation

1. Put the AuthX `.jar` file into Velocity's `plugins/` directory.
2. Put the latest **LimboAPI** `.jar` into the same `plugins/` directory.
3. Restart the Velocity proxy.
4. Edit configuration as needed.
5. Run `/authx reload` to apply config and language changes without a full restart.
