# molly-brown

The Unsinkable Molly Brown: a full-featured Gemini server implemented in Go.

For more info on Gemini see https://gemini.circumlunar.space or
gopher://gemini.circumlunar.space.

## Installation

The easiest way for now to install Molly Brown is to use the standard
Golang tool `go` (note I said "easiest", not "easy" - this is still a
pretty clunky manual process, sorry).  Unfortunately, you have to do a
little bit of preparation for this to work (unless you're a Go
developer yourself in which case you surely already have this done)...

### Prepare your $GOPATH

1. Create an empty directory `~/go`.
2. Set the $GOPATH environment variable to `~/go`.

(you can in fact put your $GOPATH anywhere you like, but `~/go` is the
convention)

### Fetch and build MB

Run `go get tildegit.org/solderpunk/molly-brown`.  If everything goes
well, the end result of this will be that you'll have the Molly Brown
source code sitting in `~/go/src/tildegit.org/solderpunk/molly-brown`
and an executable binary sitting at `~/go/bin/molly-brown`.  If it
makes you happier or your life easier, you can copy that binary to
`/usr/sbin/` or anywhere else.

### Configuration

In the source directory mentioned above, you should find a file named
`example.conf`.  Copy this to `/etc/molly.conf` and edit it to suit
your environment.  The default values for all possible options are
specified in the file - just uncomment and change the ones which won't
work for you.  All options are explained below in the Configuration
Options section.

### Daemonisation and launching

Currently Molly Brown just runs like an ordinary program, without
daemonising itself.  You'll need to use another program, like the one
at `http://libslack.org/daemon/`, to handle daemonising.

Currently Molly Brown is only integrated with systemd, so if you're
using anything else you'll have to handle getting it to start on boot up
yourself.  If you are using a sufficiently right-headed operating
system, the easiest way to do this is by putting your call to
`daemon` (or whatever else you use) in `/etc/rc.local`.

Setting up with systemd should be reasonably easy; copy
`molly-brown.service.example` from this directory to
`/etc/systemd/system/molly-brown.service`. Then, make any necessary
changes for your setup, and run the following:

```sh
# systemctl daemon-reload
# systemctl enable molly-brown.service
# systemctl start molly-brown.service
```

Note that Golang programs are unable to reliably change their UID once
run (a source of constant frustration to me!).  So don't start it as
root, or it'll remain as root forever.  Run it as `nobody`, or a
dedicated `molly` user.  Make sure that user has read access to the
TLS keys and write access to the specified log file.

## Configuration Options

The following options can be set in `/etc/molly.conf`:

* `Port`: The TCP port to listen for connections on (default value
  `1965`).
* `Hostname`: The hostname to respond to requests for (default value
  `localhost`).  Requests for URLs with other hosts will result in a
  status 53 (PROXY REQUEST REFUSED) response.
* `CertPath`: Path to TLS certificate in .pem format (default value
  `cert.pem`).
* `KeyPath`: Path to TLS private key in .pem format (default value
  `key.pem`).
* `DocBase`: Base directory for Gemini content (default value
  `/var/gemini/`).
* `HomeDocBase`: Requests for paths beginning with `~/username/` will
  be looked up relative to `DocBase/HomeDocBase/username/` (default
  value `users`).  Note that Molly Brown does *not* look inside user's
  actual home directories like you may expect based on experience with
  other server software.  Of course, you can symlink
  `/var/gemini/users/gus/` to `/home/gus/public_gemini/` if you want.
* `LogPath`: Path to log file (default value `molly.log`).  Note that
  all intermediate directories must exist, Molly Brown won't create
  them for you.
* `DirectorySort`: A string specifying how to sort files in automatically generated directory listings.  Must be one of "Name", "Size" or "Time" (default value "Name").
* `DirectoryReverse`: Boolean, if true automatically generated directory listings will list files in descending order of whatever `DirectorySort` is set to (default value false).
