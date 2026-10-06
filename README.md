# Capture the Flag Registration

`SA-ctf_registration` provides self-service registration for the Capture the Flag environment. It is designed to work with the modernized `SA-ctf_scoreboard` and `SA-ctf_scoreboard_admin` apps on Splunk Enterprise 10.4.

The app supports multiple CTFs at the same time. Each CTF has its own registration window, event window, image, description, search URL, scoring URL, and participant roles.

## Requirements

- Splunk Enterprise 10.4
- `SA-ctf_scoreboard`
- `SA-ctf_scoreboard_admin`
- A Splunk service account used by the registration backend
- The service account must be able to:
  - read and write the registration KV Store collections
  - read Splunk users
  - add only the CTF roles that registration is allowed to grant
- The participant role normally used by the CTF:
  - `ctf_competitor`
- The administrative roles normally used by the CTF:
  - `ctf_admin`
  - `ctf_registration_admin`
- Python 3 as provided by Splunk 10.4

The app ID is:

```text
SA-ctf_registration
```

The display name is:

```text
Capture the Flag Registration
```

## Important files

```text
SA-ctf_registration/
├── appserver/
│   └── static/
│       ├── registration.js
│       ├── registration_admin.js
│       ├── registration.css
│       └── images/
│           └── default-ctf.svg
├── bin/
│   ├── registration_core.py
│   └── registration_rest.py
├── default/
│   ├── app.conf
│   ├── collections.conf
│   ├── ctf_registration.conf
│   ├── transforms.conf
│   └── data/
│       └── ui/
│           ├── nav/
│           │   └── default.xml
│           └── views/
│               ├── admin.xml
│               └── register.xml
├── local/
│   └── registration_secrets.conf
└── metadata/
    └── default.meta
```

## Global configuration

Global settings live in:

```text
default/ctf_registration.conf
```

Example:

```ini
[general]
writer_username = svcaccount
default_participant_roles = ctf_competitor
allowed_participant_roles = ctf_competitor
default_image_url = /static/app/SA-ctf_registration/images/default-ctf.svg
```

CTF-specific times and settings do **not** belong in this file. They are stored per event in the `ctf_events` KV Store.

### Registration writer password

Do not commit the service account password to Git.

Create:

```text
local/registration_secrets.conf
```

with:

```ini
[writer]
password = REPLACE_WITH_SERVICE_ACCOUNT_PASSWORD
```

Protect the file:

```bash
chmod 600 local/registration_secrets.conf
```

When working inside a rootless Podman Splunk container:

```bash
podman exec -u splunk splunk \
  chmod 600 /opt/splunk/etc/apps/SA-ctf_registration/local/registration_secrets.conf
```

## KV Store collections

### `ctf_events`

One record exists for each CTF.

Important fields:

| Field | Purpose |
|---|---|
| `ctf_id` | Stable unique identifier for the CTF |
| `name` | User-facing CTF name |
| `short_description` | Text shown on the event card |
| `description` | Full event description |
| `image_url` | Local or reachable image path |
| `registration_opens` | Registration start time |
| `registration_closes` | Registration end time |
| `event_starts` | CTF start time |
| `event_ends` | CTF end time |
| `search_url` | Splunk/search URL for participants |
| `search_url_desc` | Friendly description for the search URL |
| `scoring_url` | Optional scoring URL |
| `participant_roles` | Splunk role or roles granted after registration |
| `enabled` | Whether the event is visible/usable |
| `allow_updates` | Whether users may edit registration while registration is open |

### `ctf_registrations`

A user can register for more than one CTF.

The logical registration key is:

```text
ctf_id + Username
```

Important fields include:

```text
ctf_id
Username
DisplayUsername
Team
FirstName
LastName
Email
SearchUrl
SearchUrlDesc
ScoringUrl
status
registered_at
updated_at
```

## Registration and event states

Registration and event timing are independent.

Registration states:

```text
DISABLED
UPCOMING
OPEN
CLOSED
```

Event states:

```text
UPCOMING
IN_PROGRESS
COMPLETED
```

This allows late registration if desired. For example, registration may remain open after the event starts.

## Accessing the app

Participant registration page:

```text
/en-US/app/SA-ctf_registration/register
```

Registration administration page:

```text
/en-US/app/SA-ctf_registration/admin
```

The app root should open the registration view:

```text
/en-US/app/SA-ctf_registration
```

## Creating a new CTF

Open:

```text
Capture the Flag Registration → CTF Registration Admin
```

or browse directly to:

```text
/en-US/app/SA-ctf_registration/admin
```

Select **New CTF** and populate the following fields.

### 1. CTF ID

Use a stable, lowercase identifier.

Example:

```text
asteron-easy-2026
```

Recommended format:

```text
<event>-<difficulty>-<year>
```

Do not reuse a `ctf_id` for a different event.

### 2. Name

Example:

```text
Asteron Utilities: Easy
```

### 3. Short description

This appears on the registration card.

Example:

```text
Investigate a simulated intrusion into Asteron Utilities' U.S. environment.
```

### 4. Full description

This is shown when the participant opens the event details.

### 5. Image

The admin page supports direct image upload. Enter the CTF ID first, then choose a PNG, JPEG, or WebP image up to 5 MB. Uploaded images are stored under:

```text
appserver/static/images/uploads/
```

and the event `image_url` is populated automatically with a URL such as:

```text
/static/app/SA-ctf_registration/images/uploads/asteron-easy-2026.png
```

The image picker includes a preview and a **Use Default Image** button. The raw image URL/path field remains available under **Advanced: image URL/path** for manually managed images.

If no custom image is supplied, use:

```text
/static/app/SA-ctf_registration/images/default-ctf.svg
```

### 6. Registration opens

Set the date and time participants are allowed to start registering.

### 7. Registration closes

Set the final date and time new registrations or permitted registration updates are accepted.

### 8. Event starts

Set the date and time the actual CTF begins.

### 9. Event ends

Set the date and time the CTF ends.

### 10. Search URL

Set the Splunk/search URL participants should use for this event.

Example:

```text
http://192.168.1.250:8000
```

### 11. Participant roles

Normally:

```text
ctf_competitor
```

The value must also be allowed by:

```ini
allowed_participant_roles = ctf_competitor
```

Do not allow registration to grant broad administrative roles.

### 12. Enabled

Enable the CTF only when it should be visible and available to the registration workflow.

### 13. Allow registration updates

Enable this if registered users may edit their display name, team, or other registration information while the registration window remains open.

## Time-bounding a CTF

Each CTF has four timestamps:

```text
registration_opens
registration_closes
event_starts
event_ends
```

Typical example:

```text
Registration opens:  2026-10-01 08:00
Registration closes: 2026-10-10 20:00
Event starts:        2026-10-12 08:00
Event ends:          2026-10-14 20:00
```

The app enforces registration times server-side. Hiding or modifying browser controls does not bypass the registration window.

### Allowing late registration

The registration close time may intentionally be later than the event start time.

Example:

```text
Event starts:        2026-10-12 08:00
Registration closes: 2026-10-12 12:00
```

That allows participants to register during the first four hours of the event.

## Enabling a CTF for registration

A CTF must meet all of these conditions before registration is accepted:

1. The event record exists.
2. `enabled` is true.
3. Current server time is on or after `registration_opens`.
4. Current server time is on or before `registration_closes`.
5. The requested participant role is permitted by the registration configuration.

When these conditions are met, the registration card shows:

```text
REGISTRATION OPEN
```

A successful registration:

1. identifies the authenticated Splunk user
2. records the user's registration against the selected `ctf_id`
3. adds any missing permitted participant role, normally `ctf_competitor`
4. preserves the user's existing Splunk roles

## Concurrent CTFs

Multiple CTF records may overlap.

Example:

```text
Asteron Easy
Registration: Oct 1-10
Event:        Oct 12-14

Asteron Medium
Registration: Oct 3-15
Event:        Oct 20-22

Holiday Hunt
Registration: Oct 5-Nov 1
Event:        Nov 5-7
```

A participant may register for all three. Registrations remain separate because they are scoped by `ctf_id`.

## Closing registration

There are two normal ways to stop registration.

### Automatic close

Allow the configured `registration_closes` time to pass.

No manual action is required. The server will reject new registrations after the close time.

### Immediate close

Edit the CTF and either:

- move `registration_closes` to the current/past time, or
- disable the event if it should no longer be available at all

Use a time-based close when the event should remain visible but registration should stop.

Use **Enabled = false** when the event should be administratively disabled.

## Closing out a CTF

After the event ends:

1. verify `event_ends` is correct
2. verify registration is closed
3. retain the event record so historical registrations remain associated with the correct `ctf_id`
4. export or archive participant and scoring data if required
5. do not reuse the same `ctf_id` for a different CTF
6. disable the CTF when you no longer want it presented by the registration application

Do not delete registration records merely to clean up the UI. They provide the relationship between a participant and the CTF they entered.

## Updating an existing CTF

Open the admin page, choose the event, make the required changes, and save it.

The `ctf_id` is the stable identifier and should not be changed after questions, answers, hints, registrations, or scores have been associated with the event.

## Participant workflow

1. User authenticates to Splunk.
2. User opens **Capture the Flag Registration**.
3. The app displays eligible upcoming/current CTF cards.
4. User opens the desired CTF.
5. User enters registration details.
6. The backend validates the event and registration window.
7. The registration is stored using `ctf_id + Username`.
8. Required CTF access roles are added.
9. The participant opens **Capture the Flag** for the selected event.

## Troubleshooting

### App is hidden

Verify:

```ini
[ui]
is_visible = 1
label = Capture the Flag Registration
```

in:

```text
default/app.conf
```

### `/app/SA-ctf_registration` returns 404

Verify this file exists:

```text
default/data/ui/nav/default.xml
```

with:

```xml
<nav>
  <view name="register" default="true"/>
  <view name="admin"/>
</nav>
```

### Page says `Missing [registration] configuration`

That indicates the old single-event backend is still installed.

The multi-event version uses:

```ini
[general]
```

and stores event-specific configuration in `ctf_events`.

### Old registration page appears after deployment

Splunk Web/browser static assets may be cached. Confirm the installed files are current, restart Splunk, and test in a private browser window.

### Logs

Registration backend log:

```text
$SPLUNK_HOME/var/log/splunk/ctf_registration.log
```

For the rootless Podman deployment:

```bash
podman exec -u splunk splunk \
  tail -f /opt/splunk/var/log/splunk/ctf_registration.log
```

## Testing

From the source repo:

```bash
python3 -m unittest discover -s tests -v
```

## Related apps

- `SA-ctf_scoreboard` — participant questions, submissions, hints, and scoring views
- `SA-ctf_scoreboard_admin` — administrator content and scoring management

## Create a CTF and load questions, answers, and hints together

Starting with version 1.3.0, **CTF Registration Admin** can create the event and load its scoreboard content in the same form. Version 1.3.1 adds independent content updates, so questions, answers, or hints can be replaced without re-uploading the other files.

Open:

```text
/en-US/app/SA-ctf_registration/admin
```

Select **New CTF** (or edit an existing event), configure the event, then optionally select any of these CSV files:

```text
ctf_questions_staged.csv
ctf_answers_staged.csv
ctf_hints_staged.csv
```

The files use the current multi-CTF schemas:

```csv
ctf_id,Number,Question,StartTime,EndTime,BasePoints,AdditionalBonusPoints,AdditionalBonusInstructions
```

```csv
ctf_id,Number,Answer
```

```csv
ctf_id,Number,HintNumber,Hint,HintCost
```

The `ctf_id` in every row must exactly match the CTF ID being created or edited.

When one or more files are selected and **Save CTF** is pressed, the registration backend combines the uploaded files with the event's existing content, validates the resulting complete content set, and then replaces only the selected content types. It writes:

- questions to `SA-ctf_scoreboard_admin / ctf_questions`
- answers to `SA-ctf_scoreboard_admin / ctf_answers`
- hints to `SA-ctf_scoreboard_admin / ctf_hints`

For each selected content type, existing rows for the same `ctf_id` are updated, new rows are added, and rows no longer present in that uploaded file are removed. Content types without a selected file are retained unchanged. Other CTFs are not changed.

### Question scoring window

By default, **Use the CTF event start/end as the scoring window for every imported question** is enabled. This removes the need to separately synchronize `StartTime` and `EndTime` values in the question CSV with the event form.

Clear the checkbox only when the CSV intentionally contains different per-question scoring windows.

### Permissions

Creating/editing event metadata is available to the registration administrative roles. Importing questions/answers/hints additionally requires either:

```text
admin
ctf_admin
```

This is intentional because answers and hints are protected CTF content.

### Editing an existing CTF

If no CSV files are selected while editing an event, existing questions, answers, and hints are left unchanged.

You may replace questions, answers, or hints independently. The backend validates the effective full set before writing anything. For example, replacing only the questions CSV succeeds only when the retained answers and hints still reference valid question numbers and every question still has an answer.

## Participant event cards

The participant registration page renders CTF events as compact cards instead of stretching a single event across the full page. Event artwork is displayed with `object-fit: contain` in a 16:9 frame so the complete image remains visible. Selecting a card opens the larger event-detail and registration panel below it.
