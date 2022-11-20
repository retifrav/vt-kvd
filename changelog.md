# Changelog

<!-- MarkdownTOC -->

- [0.5.0](#050)
- [0.4.0](#040)
- [0.3.0](#030)
- [0.2.0](#020)
- [0.1.0](#010)

<!-- /MarkdownTOC -->

## 0.5.0

Released on `2022-11-20`.

- previewing the list of files discovered while scanning the folder
    + also showing a warning if too many files were discovered
- displaying checking progress in the GUI
- not failing right away if some files have never been scanned at VirusTotal
    + instead those still go to results but as empty rows with an explanation tooltip
- when VirusTotal doesn't have `type_tag` for the object, show only `type_description`
- better looking loading/busy indicators
- added application icon

## 0.4.0

Released on `2022-11-09`.

- highlighting dangerous results
- openning full VirusTotal reports on the website
- safeguarding libmagic import/discovery

## 0.3.0

- getting current user VirusTotal API requests quotas
- sending user agent to VirusTotal API

## 0.2.0

- scanning directories
- showing results as a table

## 0.1.0

- first version
- reading VirusTotal API key from a config file
- calculating SHA1 hashes and getting existing scan results
