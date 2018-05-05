This is an SSH server which does reverse TCP port forwarding.
It does not provide a shell.

The interesting bit is the authentication procedure: it assumes you
have port 22 reverse-forwarded and connects back to the client to
grab its SSH server public key. In other words in order to be able
to establish a connection, the client should have their own server
up and running (and reachable via a reverse-forwarded TCP port 22).

To avoid clashing with an existing SSH server on the host, this
implementation binds to port 2200/tcp.

Remember to supply host keys — they should reside in the working
directory and be matched by "id_*" wildcard ("*.pub" for public,
everything else for private). `ssh-keygen -t rsa -f id_rsa` should
work.
