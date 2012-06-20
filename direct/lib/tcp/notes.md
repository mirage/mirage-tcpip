The sliding window has 3 edges, which can only be incremented.  The type of the
edges is SEQ, which is implemented in Sequence.ml

+------------------------------------------------+
|               |         |     |                |
+------------------------------------------------+
SEQ.min         L         M     R                SEQ.max

The values satisfy { L <= M <= R }. SEQ values roll over upon overflow, so this
relation holds as we approach SEQ.max.

TCP has two sliding windows with separate sequence tracking: for the receive
and transmit channels.  Notation below is 'if (condition) | (edge trigger):'

Receive channel
---------------
L = Data that has been received and acked, but not consumed by the application.
M = Data that has been received and acked, lower edge of valid received traffic.
R = Maximum edge of receive window 

rx window = (R - M)
if (M-L)==0 | (>0): application readers are woken
if (R-M)==0 | (>0): application takes buffer and rx window opens (send dup ack?)
if M | (M+)       : update rx window value

Transmit channel 
----------------
L = Data that has been transmitted and acked from the other side.
M = Data that has been transmitted, but is unacked from the other side.
R = Edge of transmit window
snd_una is the value of L+1
snd_nxt is the value of M+1

tx window = (R - M)
if (M-L)>0 | (=0) : tx inflight drops to 0, so set Nagle 
if (R-M)==0 | (>0): application writers are woken.
