rule linux_raw_socket_x86_64
{
    meta:
        description = "Detects programs that potentially use raw sockets on x86_64 Linux"
        author = "Daniel Roberson"

    strings:
        $SOCK_RAW_call_inet6 = {
		    be 03 00 00 00 // SOCK_RAW
			   [0-8]
			bf 0a 00 00 00 // AF_INET6
			   [0-8]
			e8 ?? ?? ?? ?? // call (probably socket)
	    }

		$SOCK_RAW_call_inet = {
			be 03 00 00 00 // SOCK_RAW
			   [0-8]
			bf 02 00 00 00 // AF_INET
			   [0-8]
			e8             // call (probably socket)
	    }

		$socket = "socket"

    condition:
        any of ($SOCK_RAW_call*) and $socket
}
