import json

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.56.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="23">
        <state state="open"/>
        <service name="telnet" product="BusyBox" version="1.31"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.24"/>
        <script id="ssl-cert" output="self-signed certificate"/>
      </port>
    </ports>
  </host>
  <runstats><finished elapsed="1.23" summary="done"/></runstats>
</nmaprun>
"""


def test_network_scan_profile_planning():
    from vulnclaw.agent.network_scan import build_nmap_command, build_nmap_plan

    plan = build_nmap_plan(profile="thorough")

    assert plan.profile == "thorough"
    assert plan.ports == "1-65535"
    assert plan.timing == 3
    command = build_nmap_command("/usr/bin/nmap", "192.168.56.10", plan)
    assert command[:2] == ["/usr/bin/nmap", "-v"]
    assert "--script" in command
    assert "default,safe" in command
    assert command[-1] == "192.168.56.10"


def test_build_nmap_command_deescalates_without_root(monkeypatch):
    from vulnclaw.agent.network_scan import (
        build_nmap_command,
        build_nmap_plan,
        deescalate_nmap_argv,
        without_privileged_nmap_args,
    )

    plan = build_nmap_plan(profile="thorough")
    assert "-O" in plan.args

    monkeypatch.setattr("vulnclaw.agent.network_scan.nmap_has_raw_socket_access", lambda: False)
    command = build_nmap_command("/usr/bin/nmap", "192.168.56.10", plan)
    assert "-O" not in command
    assert "-sS" not in command

    stealth = build_nmap_plan(profile="stealth")
    assert without_privileged_nmap_args(stealth.args) == ("-q", "-sT", "-f")
    assert "-O" not in deescalate_nmap_argv(
        ["/usr/bin/nmap", "-sS", "-O", "-sV", "-oX", "-", "192.168.56.10"]
    )


def test_network_scan_adaptive_uses_prior_ports():
    from vulnclaw.agent.network_scan import build_nmap_plan

    plan = build_nmap_plan(
        profile="adaptive",
        prior_recon={
            "network_services": [
                {"host": "192.168.56.10", "port": 22, "protocol": "tcp"},
                {"host": "192.168.56.10", "port": 8443, "protocol": "tcp"},
            ]
        },
    )

    assert plan.ports == "22,8443"
    assert plan.timing == 3


def test_detect_connected_wifi_target_uses_active_wireless_ipv4(monkeypatch):
    import vulnclaw.agent.network_scan as network_scan

    monkeypatch.setattr(network_scan, "_wifi_interfaces", lambda: ["wlp2s0"])
    monkeypatch.setattr(network_scan, "_interface_is_up", lambda interface: True)
    monkeypatch.setattr(
        network_scan,
        "_interface_ipv4_network",
        lambda interface: network_scan.WifiScanTarget(
            interface=interface,
            address="192.168.1.42",
            cidr="192.168.1.0/24",
        ),
    )

    target = network_scan.detect_connected_wifi_target()

    assert target.interface == "wlp2s0"
    assert target.address == "192.168.1.42"
    assert target.cidr == "192.168.1.0/24"


def test_parse_nmap_xml_structured_ranks_weak_links():
    from vulnclaw.agent.network_scan import parse_nmap_xml_structured, summarize_network_scan

    structured = parse_nmap_xml_structured(NMAP_XML, "192.168.56.10")

    assert len(structured["open_services"]) == 2
    assert structured["weak_links"][0]["risk"] == "unencrypted_protocol"
    assert structured["weak_links"][0]["severity"] == "High"
    assert structured["weak_links"][1]["risk"] == "web_surface"
    summary = summarize_network_scan(structured)
    assert "Weak-link candidates: 2" in summary
    assert "192.168.56.10:23" in summary


def test_attach_network_scan_to_session_keeps_weak_links_as_recon():
    from vulnclaw.agent.context import SessionState
    from vulnclaw.agent.network_scan import (
        attach_network_scan_to_session,
        parse_nmap_xml_structured,
    )

    session = SessionState(target="192.168.56.10")
    structured = parse_nmap_xml_structured(NMAP_XML, "192.168.56.10")

    attach_network_scan_to_session(session, structured, profile="fast")

    assert session.recon_data["network_scans"][0]["profile"] == "fast"
    assert len(session.recon_data["network_services"]) == 2
    assert {f['risk'] for f in session.recon_data['network_scans'][0]['weak_links']} == {
        "unencrypted_protocol",
        "web_surface",
    }
    assert session.findings == []
    assert session.step_records[-1].action == "network scan"
    assert json.loads(session.step_records[-1].detail)["target"] == "192.168.56.10"
