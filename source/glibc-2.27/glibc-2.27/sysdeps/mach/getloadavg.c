/* Get system load averages.  Mach version.
   Copyright (C) 1999-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <mach.h>
#include <mach/host_info.h>
#include <hurd.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>


/* Put the 1 minute, 5 minute and 15 minute load averages
   into the first NELEM elements of LOADAVG.
   Return the number written (never more than 3, but may be less than NELEM),
   or -1 if an error occurred.  */

int
getloadavg (double loadavg[], int nelem)
{
  host_load_info_data_t info;
  mach_msg_type_number_t size = HOST_LOAD_INFO_COUNT;
  error_t err;
  int i;

  err = __host_info (__mach_host_self (), HOST_LOAD_INFO,
		     (host_info_t) &info, &size);
  if (err)
    return __hurd_fail (err);
  if (size < HOST_LOAD_INFO_COUNT)
    return __hurd_fail (EGRATUITOUS);

  if (nelem > 3)
    nelem = 3;
  for (i = 0; i < nelem; ++i)
    loadavg[i] = (double) info.avenrun[i] / (double) LOAD_SCALE;

  return i;
}