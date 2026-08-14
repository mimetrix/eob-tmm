#!/bin/sh
# Which functions does the traffic ACTUALLY execute? Arm each address in slot 0,
# drive requests, read `fired`, disarm.
#
# RUN THIS BEFORE BUILDING ANY TRACEPOINT. A hook on a function the traffic never
# reaches produces silence that is indistinguishable from "the condition never
# occurred" --- and three subsystems have already looked reachable and not been:
# PSM (http_psm_headers, 0 fires), analytics (http_analytics_get_all_stats,
# 0 fires), and most of the HTTP data/field layer. A plain GET through a Gateway
# to a static backend exercises very little of TMM.
#
# Sequential, not parallel: there are 8 slots but STATUS reports slot 0 only
# (ls_vm_stats(0, &st) in ls_vm_load.c), so a parallel survey cannot be read back.
#
# Addresses come from substrate/mk_hook_map.py against the DEPLOYED build. Edit
# the pod name and socket below, or pass them in.
#
# usage: bnk-survey-hooks.sh 0xccff00 0xca7700 ...
# Which functions does ordinary BNK traffic actually execute? Arm each in slot 0,
# drive traffic, read `fired`, disarm. One at a time because STATUS reports slot 0
# only. This is the check that should precede any tracepoint work: a hook on a
# function the traffic never reaches produces silence indistinguishable from
# "the condition never happened".
P=f5-tmm-6784b64f56-wcssk; S=/tmp/ls_load.sock.24
send() { kubectl exec -i $P -c f5-tmm -- ncat -U -w4 $S < "$1" 2>/dev/null | tail -1; }
prev=$(send /tmp/status.bin | grep -oE "fired=[0-9]+" | cut -d= -f2)
for a in "$@"; do
  python3 -c "
import struct,sys
def m(op,slot=0,mode=2,hook=b'',pl=b''):
    x=struct.pack('<IIBxxxI',op,slot,mode,len(pl))+b'\0'*32+hook.ljust(64,b'\0')+b'\0'*16+b'\0'*64
    return x+pl
sys.stdout.buffer.write(m(0x1003,hook=b'$a'))" > /tmp/a.bin
  python3 -c "
import struct,sys
def m(op,slot=0,mode=2,hook=b'',pl=b''):
    x=struct.pack('<IIBxxxI',op,slot,mode,len(pl))+b'\0'*32+hook.ljust(64,b'\0')+b'\0'*16+b'\0'*64
    return x+pl
sys.stdout.buffer.write(m(0x1004,hook=b'$a'))" > /tmp/d.bin
  r=$(send /tmp/a.bin)
  case "$r" in OK*) ;; *) printf "  %-12s ARM-REFUSED\n" "$a"; continue;; esac
  for i in 1 2 3 4 5 6; do kubectl exec client -- curl -s -m 4 -o /dev/null http://11.11.11.99/ >/dev/null 2>&1; done
  now=$(send /tmp/status.bin | grep -oE "fired=[0-9]+" | cut -d= -f2)
  d=$((now - prev)); prev=$now
  printf "  %-12s fired+%-4s %s\n" "$a" "$d" "$([ "$d" -gt 0 ] && echo '<== ON THE PATH' || echo '')"
  send /tmp/d.bin >/dev/null
done
