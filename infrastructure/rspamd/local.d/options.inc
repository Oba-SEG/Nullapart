# Nullapart local options.
#
# Restrict Rspamd's "local networks" skip list to loopback. The packaged
# default treats RFC1918/docker networks as local, which silently skipped
# SPF/DKIM/DMARC for every lab message and left domain-authentication
# evidence permanently empty. Only loopback may skip auth checks.
local_networks = "$LOCAL_CONFDIR/local.d/local_networks.map";
