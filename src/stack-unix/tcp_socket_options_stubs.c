/*
 * Copyright (c) 2017 Docker Inc
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdint.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/fail.h>
#include <caml/bigarray.h>
#include <caml/unixsupport.h>

#ifdef WIN32
#else
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#endif

/* Round up to the next second */
#define SECONDS_OF_MILLISECONDS(x) ( (x + 999) / 1000 )

CAMLprim value
caml_tcp_set_keepalive_params(value v_fd, value v_time, value v_interval, value v_probe)
{
  CAMLparam4(v_fd, v_time, v_interval, v_probe);
#ifdef WIN32
  SOCKET s = Socket_val(v_fd);
  DWORD dwBytesRet=0;
  struct tcp_keepalive alive;
  alive.onoff = TRUE;
  alive.keepalivetime = Int_val(v_time); /* ms */
  alive.keepaliveinterval = Int_val(v_interval); /* ms */
  if (WSAIoctl(s, SIO_KEEPALIVE_VALS, &alive, sizeof(alive),
    NULL, 0, &dwBytesRet, NULL, NULL) == SOCKET_ERROR) {
    win32_maperr(WSAGetLastError());
  }
#elif DARWIN
  int s = Int_val(v_fd);
  int optval = SECONDS_OF_MILLISECONDS(Int_val(v_time));
  if(setsockopt(s, IPPROTO_TCP, TCP_KEEPALIVE, &optval, sizeof optval) < 0) {
    uerror("setsockopt", Nothing);
  }
  optval = SECONDS_OF_MILLISECONDS(Int_val(v_interval));
  if(setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &optval, sizeof optval) < 0) {
    uerror("setsockopt", Nothing);
  }
  optval = Int_val(v_probe);
  if(setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, &optval, sizeof optval) < 0) {
    uerror("setsockopt", Nothing);
  }
#elif LINUX
  int s = Int_val(v_fd);
  int optval = SECONDS_OF_MILLISECONDS(Int_val(v_time));
  if(setsockopt(s, SOL_TCP, TCP_KEEPIDLE, &optval, optlen) < 0) {
    uerror("setsockopt", Nothing);
  }
  optval = SECONDS_OF_MILLISECONDS(Int_val(v_interval));
  if(setsockopt(s, SOL_TCP, TCP_KEEPINTVL, &optval, sizeof optval) < 0) {
    uerror("setsockopt", Nothing);
  }
  optval = Int_val(v_probe);
  if(setsockopt(s, SOL_TCP, TCP_KEEPCNT, &optval, sizeof optval) < 0) {
    uerror("setsockopt", Nothing);
  }
#else
  fprintf(stderr, "Warning: setting TCP keep-alive parameters not supported on this platform\n");
#endif
  CAMLreturn(Val_unit);
}
