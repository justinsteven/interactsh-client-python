# About

This is a Python implementation of [interactsh-client](https://github.com/projectdiscovery/interactsh)

It can:

* Generate a new session with a public or private Interactsh server (with optional authentication via a 'token' value)
* Serialize/deserialize sessions to/from Python dictionaries (Could be useful for saving and restoring sessions)
* Poll for interactions, returning them as Python objects which are able to format themselves using Markdown

# `escape_markdown()`

This code depends on [disnake's](https://docs.disnake.dev/en/stable/) `escape_markdown()`. If disnake is not installed, you'll get a complaint on STDERR. Things will work fine without an `escape_markdown()` but the Markdown representations of interactions could become broken given interaction data that contains Markdown sequences.

# It works on my machine, it works for my use cases (so far)

Hopefully it's useful to you. YMMV, here be dragons, etc etc.

# Demo

See also: the doctests

```raw
% python3
Python 3.9.2 (default, Feb 28 2021, 17:03:44)
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from interactsh_client import InteractshSession, public_interactsh_servers
>>> from random import choice
>>> # Create a new InteractshSession with a random CID (Correlation ID), key, etc.
>>> i = InteractshSession.new(choice(public_interactsh_servers))
>>> # Generate an interaction hostname
>>> i.generate_hostname()
'5f0p1gdfugogroav2m0bzjcab395852vt.oast.fun'
>>> # Interact with a generated hostname
>>> import requests
>>> requests.get("https://" + i.generate_hostname())
<Response [200]>
>>> # Poll for interactions. For each interaction, print it, and print it as a Markdown message
>>> # (Note: Markdown code fence sequences in the below have been transformed to "'''" so as to not break the formatting of this document)
>>> for interaction in i.poll():
...   print(interaction)
...   print()
...   print(interaction.to_markdown())
...   print("---")
...
InteractshDNSInteraction(unique_id='5f0p1gdfugogroav2m0bn5tt5ineqoevy', full_id='5f0p1gdfugogroav2m0bn5tt5ineqoevy', host_basename='oast.fun', raw_request=';; opcode: QUERY, status: NOERROR, id: 51103\n;; flags: cd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; QUESTION SECTION:\n;5f0p1gdfugogroav2m0bn5tt5ineqoevy.oast.fun.\tIN\t A\n\n;; ADDITIONAL SECTION:\n\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags: do; udp: 4096\n', remote_address='REDACTED', timestamp=datetime.datetime(2022, 12, 30, 5, 33, 3, 742503, tzinfo=datetime.timezone.utc), q_type='A', raw_response=';; opcode: QUERY, status: NOERROR, id: 51103\n;; flags: qr aa cd; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 2\n\n;; QUESTION SECTION:\n;5f0p1gdfugogroav2m0bn5tt5ineqoevy.oast.fun.\tIN\t A\n\n;; ANSWER SECTION:\n5f0p1gdfugogroav2m0bn5tt5ineqoevy.oast.fun.\t3600\tIN\tA\t206.189.156.69\n\n;; AUTHORITY SECTION:\n5f0p1gdfugogroav2m0bn5tt5ineqoevy.oast.fun.\t3600\tIN\tNS\tns1.oast.fun.\n5f0p1gdfugogroav2m0bn5tt5ineqoevy.oast.fun.\t3600\tIN\tNS\tns2.oast.fun.\n\n;; ADDITIONAL SECTION:\nns1.oast.fun.\t3600\tIN\tA\t206.189.156.69\nns2.oast.fun.\t3600\tIN\tA\t206.189.156.69\n')

**DNS** (A) request from REDACTED for 5f0p1gdfugogroav2m0bn5tt5ineqoevy.oast.fun at 2022-12-30 05:33:03.742503+00:00
---
InteractshHTTPInteraction(unique_id='5f0p1gdfugogroav2m0bn5tt5ineqoevy', full_id='5f0p1gdfugogroav2m0bn5tt5ineqoevy', host_basename='oast.fun', raw_request='GET / HTTP/1.1\r\nHost: 5f0p1gdfugogroav2m0bn5tt5ineqoevy.oast.fun\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nUser-Agent: python-requests/2.25.1\r\n\r\n', remote_address='REDACTED', timestamp=datetime.datetime(2022, 12, 30, 5, 33, 4, 183028, tzinfo=datetime.timezone.utc), raw_response='HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=utf-8\r\nServer: oast.fun\r\n\r\n<html><head></head><body>yveoqeni5tt5nb0m2vaorgogufdg1p0f5</body></html>')

**HTTP** request from REDACTED to 5f0p1gdfugogroav2m0bn5tt5ineqoevy.oast.fun at 2022-12-30 05:33:04.183028+00:00

'''
GET / HTTP/1.1
Host: 5f0p1gdfugogroav2m0bn5tt5ineqoevy.oast.fun
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
User-Agent: python-requests/2.25.1


'''

'''
HTTP/1.1 200 OK
Connection: close
Content-Type: text/html; charset=utf-8
Server: oast.fun

<html><head></head><body>yveoqeni5tt5nb0m2vaorgogufdg1p0f5</body></html>
'''
---
```
