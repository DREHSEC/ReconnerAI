# Reconner Guided Capture (Chrome MV3)

This unpacked DevTools extension passively records request/response pairs that
match an explicit hostname or URL-prefix scope. It exports
`reconner-capture/v1` JSON for the Reconner **Guided Analyze** importer.

## Install and use

1. Open `chrome://extensions`, enable Developer mode, and choose **Load unpacked**.
2. Select this directory.
3. Open DevTools on the target tab and select the **Reconner** panel.
4. Enter one or more authorized target hostnames/URL prefixes and an identity
   label, then start capture and browse the application normally.
5. Stop and export the JSON file. Import it from Reconner's Guided Analyze page.

The collector requires DevTools to remain open. It does not attach the debugger,
modify traffic, replay requests, or contact Reconner/targets on its own. Request
and response bodies larger than 2 MiB are omitted. The exported file can contain
cookies, tokens and private response data; handle it as a credential file and
delete it after encrypted import.
