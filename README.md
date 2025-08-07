# Interactsh Collaborator - Revised

[![Build and Publish Release](https://github.com/TheArqsz/interactsh-collaborator-rev/actions/workflows/release.yml/badge.svg)](https://github.com/TheArqsz/interactsh-collaborator-rev/actions/workflows/release.yml)

This is a Burp Suite extension for OOB testing with Interact.sh.

![Interactsh-Collaborator](assets/interactsh-demo.gif)

## About This Fork

I forked this project because the original repository appears to be unmaintained. [The last commit](https://github.com/wdahlenburg/interactsh-collaborator/commit/dd92e5573263bc7b341ed1b980d705dba8417d92) was on August 5, 2023, and several pull requests and issues have been ignored since then.

The goal of this fork is to keep the project alive, incorporate useful community contributions, and add my own improvements. This version incorporates some changes from the following pull requests to the original repository:

- [PR #22](https://github.com/wdahlenburg/interactsh-collaborator/pull/22): Updated vulnerable dependencies.
- [PR #19](https://github.com/wdahlenburg/interactsh-collaborator/pull/19): Added a "Poll Now" button.
- [PR #18](https://github.com/wdahlenburg/interactsh-collaborator/pull/18): Major performance improvements, UI enhancements, and better table controls.

## Changelog

### v1.1

This fork begins at version 1.1, building on the original [1.0.2-dev](https://github.com/wdahlenburg/interactsh-collaborator/releases/tag/v1.0.2) code.

Changes:

- Major performance improvement - generating a new payload no longer creates a new client and thread. The extension now uses a single client, which makes it much faster and more stable.
- New features:
	- Added a **Refresh** button to manually check for interactions.
	- Added a **Clear log** button to clear the results table.
	- Added a **Regenerate Interactsh Session** button that forces current session to be deregistered and creates a new one.
	- Added a **Copy URL to clipboard** button that, similarily to the Collaborator's one, simply copies current session's Interactsh URL to the system clipboard
	- Added Collaborator-like filtering feature for different types of payloads
	- Added a built-in viewer for HTTP/S request and response details.
	- Added "unread" count of new entries (visible in the tab's title)
- Fixes & UX:
	- The polling interval setting is now reliably applied.
	- The interactions table now supports selecting individual cells, rows, and columns for copying.
	- The user interface was refreshed to better match the look and feel of Burp's native tools.
- Security - patched vulnerable dependencies in pom.xml.
- Added Dockerfile - You can now easily build the extension locally using Docker.

## About

This extension implements the client side logic from [interactsh-client](https://github.com/projectdiscovery/interactsh/). It allows you to generate new domains that can be used for OOB testing. If you host your own version of Interactsh you can configure it in the **Configuration** tab.

This extension works alongside the BurpSuite's Collaborator.

## Build

### Docker (recommended)

```bash
docker build --output ./build-output .
```

The directory `./build-output` will contain all generated jars.

### Releases

You can download the `interactsh-collaborator.jar` from [the releases page](https://github.com/TheArqsz/interactsh-collaborator-rev/releases).

### Locally

1. `mvn package`
2. Add the target/collaborator-1.x.x-dev-jar-with-dependencies.jar file as a new Java extension in Burpsuite

## Usage

After the extension is installed (as a jar) you should be able to see the Interactsh tab. Navigate to the tab and click the button labeled `Copy URL to clipboard`.

This button will copy the already generated domain name to your clipboard. The domain name and correlation (session) id will also be logged to the extension output.

You can use this domain name in any OOB testing. To generate a sample event you can visit that domain in a new browser tab.

Data should populate after a few seconds into the table with details about what type of OOB interaction occurred.

Try adjusting the poll time to a shorter value when you expect active results.
