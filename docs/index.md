# SnitchProxy

**Egress security scanner — catch data leaks before they leave your app.**

SnitchProxy is a dual-mode egress security testing tool. Deploy it as a **fake external API** to catch credential leaks, or as a **transparent proxy** to audit real integration traffic. Either way, it snitches on your app when sensitive data tries to escape.

## The Problem

Every security tool today tests *inbound* traffic — is your server safe from attackers? Nobody tests *outbound* traffic — is your app safe to connect to? Apps routinely leak credentials, session tokens, PII, and internal headers to third-party APIs. There's no standard tool to catch this.

## How It Works

**Mode 1 — Decoy Endpoint** (like httpbin with teeth):

1. Point your app at SnitchProxy instead of a real external API
2. SnitchProxy echoes every request AND evaluates it against your assertions
3. Violations are collected and reported via the admin API

**Mode 2 — Transparent Proxy** (like Toxiproxy for security):

1. Route your app's outbound traffic through SnitchProxy
2. Traffic flows to real external APIs, but SnitchProxy inspects everything
3. Violations are reported via the admin API and final report

## Part of the VibeWarden Ecosystem

| Tool | Role |
|------|------|
| [VibeWarden](https://vibewarden.dev/docs) | Egress proxy — the lock |
| **SnitchProxy** | Egress assertion engine — the lock tester |
| [httptape](https://github.com/vibewarden/httptape) | Request recorder — the evidence |
