# ADR-062: Use an English-only MVP interface

## Status

Accepted

## Date

2026-10-27

## Context

The MVP has user-visible text embedded in the Windows and Android webview.
Dates, times, numbers, sorting, and byte counts previously inherited the
operating system locale, which could mix localized values with English text.
The project does not yet have translation catalogs, translated accessibility
labels, or a process for reviewing translated security language.

## Decision

Ship the MVP interface in English and declare the document language as
English. Format user-visible dates, times, numbers, and locale-sensitive
sorting with the explicit `en-US` locale. Keep protocol and application error
codes stable and independent from the English display strings.

Introduce a translation catalog only when the project can translate the full
interface, including accessibility labels, security warnings, errors, and
platform metadata, and can test every supported language on Windows and
Android.

## Alternatives considered

- Inherit the operating system locale for values only: rejected because it
  creates a partially localized interface and makes screenshots and support
  instructions inconsistent.
- Add an incomplete string catalog now: rejected because untranslated fallback
  text would still produce a mixed-language interface without a translation
  review process.

## Consequences

- MVP presentation is consistent across supported devices and operating system
  language settings.
- Users cannot select another interface language in the MVP.
- Adding localization later requires moving all display text and accessibility
  labels into reviewed catalogs before advertising language support.
