import type { Packet } from "./types";

let auto = 1;
type Opt = Partial<Packet>;

export function resetIds() {
  auto = 1;
}

export function tcp(t: number, src: string, sport: number, dst: string, dport: number, flags: string, o: Opt = {}): Packet {
  const payload = o.payload;
  return {
    id: o.id ?? auto++,
    t,
    src,
    dst,
    sport,
    dport,
    proto: "TCP",
    flags,
    ttl: o.ttl ?? 64,
    len: 54 + (payload?.length ?? 0),
    payload,
    info: o.info ?? `${sport} → ${dport} [${flags}]${payload ? " " + payload.split("\n")[0].slice(0, 60) : ""}`,
    label: o.label,
  };
}

export function udp(t: number, src: string, sport: number, dst: string, dport: number, o: Opt = {}): Packet {
  const payload = o.payload;
  return {
    id: o.id ?? auto++,
    t,
    src,
    dst,
    sport,
    dport,
    proto: "UDP",
    ttl: o.ttl ?? 64,
    len: 42 + (payload?.length ?? 0),
    payload,
    info: o.info ?? `${sport} → ${dport} Len=${payload?.length ?? 0}`,
    label: o.label,
  };
}

export function dns(t: number, src: string, dst: string, name: string, o: Opt = {}): Packet {
  return udp(t, src, o.sport ?? 53000 + (auto % 900), dst, 53, {
    ...o,
    payload: o.payload ?? `QUERY A ${name}`,
    info: o.info ?? `Standard query A ${name}`,
  });
}

export function http(t: number, src: string, dst: string, request: string, o: Opt = {}): Packet {
  return tcp(t, src, o.sport ?? 49000 + (auto % 900), dst, o.dport ?? 80, "PA", {
    ...o,
    payload: request,
    info: o.info ?? request.split("\n")[0],
  });
}

export function icmp(t: number, src: string, dst: string, type: number, o: Opt = {}): Packet {
  return {
    id: o.id ?? auto++,
    t,
    src,
    dst,
    proto: "ICMP",
    icmpType: type,
    ttl: o.ttl ?? 64,
    len: 74,
    payload: o.payload,
    info: o.info ?? (type === 8 ? "Echo (ping) request" : type === 0 ? "Echo (ping) reply" : `ICMP type ${type}`),
    label: o.label,
  };
}

export function arp(t: number, src: string, info: string, o: Opt = {}): Packet {
  return {
    id: o.id ?? auto++,
    t,
    src,
    dst: o.dst ?? "ff:ff:ff:ff:ff:ff",
    proto: "ARP",
    len: 42,
    info,
    payload: o.payload,
    label: o.label,
  };
}
