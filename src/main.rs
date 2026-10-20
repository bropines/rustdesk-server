// https://tools.ietf.org/rfc/rfc5128.txt
// https://blog.csdn.net/bytxl/article/details/44344855

use flexi_logger::*;
use hbb_common::{bail, config::RENDEZVOUS_PORT, ResultType};
use hbbs::{common::*, *};

const RMEM: usize = 0;

fn main() -> ResultType<()> {
    let _logger = Logger::try_with_env_or_str("info")?
        .log_to_stdout()
        .format(opt_format)
        .write_mode(WriteMode::Async)
        .start()?;
    let args = format!(
        "-c --config=[FILE] +takes_value 'Sets a custom config file'
        -b, --bind=[IP] 'Sets the IP address to bind to (default: all interfaces)'
        -p, --port=[NUMBER(default={RENDEZVOUS_PORT})] 'Sets the listening port'
        -s, --serial=[NUMBER(default=0)] '[DEPRECATED] Sets configure update serial number'
        -R, --rendezvous-servers=[HOSTS] '[DEPRECATED] Sets rendezvous servers, separated by comma'
        -u, --software-url=[URL] '[DEPRECATED] Sets download url of RustDesk software of newest version'
        -r, --relay-servers=[HOST] 'Sets the default relay servers, separated by comma'
        -M, --rmem=[NUMBER(default={RMEM})] 'Sets UDP recv buffer size, set system rmem_max first, e.g., sudo sysctl -w net.core.rmem_max=52428800. vi /etc/sysctl.conf, net.core.rmem_max=52428800, sudo sysctl –p'
        , --mask=[MASK] '[DEPRECATED] Determine if the connection comes from LAN, e.g. 192.168.0.0/16'
        -k, --key=[KEY] 'Only allow the client with the same key'
        , --must-login=[Y|N] 'Only allow the client with login'
        , --tcp-keepalive=[Y|N] 'Send keepalives to TCP/WebSocket rendezvous clients so they stay online'
        , --webrtc=[Y|N] 'Forward WebRTC signaling (SDP offer/answer, ICE candidates) between clients'
        , --ws-relay-servers=[HOSTS] 'Relays offered to WebSocket (browser) clients instead of the relay servers, separated by comma'
        , --ws-peers=[Y|N] 'Forward RequestRelay to peers registered over WebSocket (default: UDP only, as upstream)'
        , --ws-key-exchange=[Y|N] 'Also send the signed key exchange on WebSocket connections, so browser clients can check the server key (default: TCP only, as upstream)'
        , --trusted-proxies=[CIDRS] 'Reverse proxies (IPs/CIDRs, comma separated) whose X-Real-IP/X-Forwarded-For the WebSocket port honours, besides loopback'
        , --authz-url=[URL] 'Ask this HTTP endpoint before forwarding each connection attempt to a peer (default: off, as upstream)'
        , --authz-secret=[SECRET] 'Bearer secret for --authz-url (prefer AUTHZ_SECRET or --authz-secret-file)'
        , --authz-secret-file=[FILE] 'File with the bearer secret for --authz-url (wins over --authz-secret)'
        , --authz-fail-closed=[Y|N] 'Refuse connections while the --authz-url service fails (default: N, let them through)'",
    );
    init_args(&args, "hbbs", "RustDesk ID/Rendezvous Server");
    let port = get_arg_or("port", RENDEZVOUS_PORT.to_string()).parse::<i32>()?;
    if port < 3 {
        bail!("Invalid port");
    }
    let bind_addr = parse_bind_address(&get_arg("bind"))?;
    let rmem = get_arg("rmem").parse::<usize>().unwrap_or(RMEM);
    let serial: i32 = get_arg("serial").parse().unwrap_or(0);
    crate::common::check_software_update();
    RendezvousServer::start_with_bind(
        bind_addr,
        port,
        serial,
        &get_arg_or("key", "-".to_owned()),
        rmem,
    )?;
    Ok(())
}
