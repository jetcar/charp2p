# ADR-032: Opt-in desktop background running

## Status

Accepted

## Date

2026-10-06

## Context

The Settings page offers background and startup behavior (product design,
page 10). Pending invitations retry and owned invitations stay discoverable
only while the application runs. Closing the window currently exits the
application, which stops advertising, synchronization and an opted-in
contribution node (ADR-014, ADR-031). Android schedules background work
through the operating system and does not keep a hidden window alive.

## Decision

Background running is off by default and offered only on Windows builds, where
the single-instance plugin hands a second launch to the running instance and
shows its window again. When the user opts in, a window close request hides
the window instead of exiting, and the application keeps advertising,
synchronizing and contributing as it would with the window open. The Settings
page offers an explicit Quit action while the preference is enabled.

The preference is a small device-local JSON file next to the database. It
holds no secrets and is not synchronized. A missing file means closing the
window exits; an unreadable or invalid file is reported on the Settings page
and closing the window exits.

Launch at login is a separate opt-in in the same preference file, off by
default and also offered only on Windows. Enabling it registers a per-user
login entry through the Tauri autostart plugin that passes a launch argument;
disabling it removes the entry. A launch at login starts with the window
hidden only when background running is also enabled, so a hidden start always
behaves like a closed window that a second launch shows again.

## Consequences

- An opted-in Windows device stays reachable for its groups while hidden,
  using network and power as it does with the window open.
- There is no tray icon in the MVP; the user shows a hidden window by
  launching the application again and quits from Settings or by ending the
  process.
- Linux development builds and Android keep closing on window close.

## Sources

- https://v2.tauri.app/plugin/single-instance/
- https://docs.rs/tauri/2/tauri/enum.WindowEvent.html
- https://v2.tauri.app/plugin/autostart/
