/* Copyright 2016 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <err.h>
#include <inttypes.h>

#include "bitutils.h"
#include "operations.h"
#include "target.h"

#define NUM_TRIES_PROBE	5
#define FSI_SCAN_PATH "/sys/bus/platform/devices/gpio-fsi/fsi0/rescan"
#define FSI_SCAN_PATH_OLD "/sys/devices/platform/fsi-master/scan"
#define FSI_CFAM_PATH "/sys/devices/platform/gpio-fsi/fsi0/slave@00:00/raw"
#define FSI_CFAM_PATH_OLD "/sys/devices/platform/fsi-master/slave@00:00/raw"
#define FSI_SCOM_PATH "/sys/devices/platform/fsi-master/slave@00:00/"

int fsi_fd;
int scom_fd;
static int fsi_old = 0;

static uint32_t kernel_fsi_swap_endian(uint32_t data)
{
	return htobe32(data);
}

static uint32_t kernel_fsi_no_swap_endian(uint32_t data)
{
	return data;
}

static uint32_t (*swap_endian)(uint32_t) = kernel_fsi_swap_endian;

static int kernel_putscom(struct target *target, uint64_t addr, uint64_t value)
{
	int rc;

	rc = lseek(scom_fd, addr, SEEK_SET);
	if (rc < 0) {
		warn("Failed to seek %s", FSI_SCOM_PATH);
		return errno;
	}

	rc = write(scom_fd, &value, sizeof(value));
	if (rc < 0) {
		warn("Failed to write to 0x%016llx", addr);
		return errno;
	}

	return 0;

}

static int kernel_getscom(struct target *target, uint64_t addr, uint64_t *value)
{
	int rc;

	rc = lseek(fsi_fd, addr, SEEK_SET);
	if (rc < 0) {
		warn("Failed to seek %s", FSI_SCOM_PATH);
		return errno;
	}

	rc = read(fsi_fd, value, sizeof(*value));
	if (rc < 0) {
		warn("Failed to read from 0x%016llx", addr);
		return errno;
	}

	return 0;

}

static int kernel_fsi_getcfam(struct target *target, uint64_t addr64, uint64_t *value)
{
	int rc;
	uint32_t data;
	uint32_t addr = (addr64 & 0x7ffc00) | ((addr64 & 0x3ff) << 2);

	rc = lseek(fsi_fd, addr, SEEK_SET);
	if (rc < 0) {
		warn("Failed to seek %s", FSI_CFAM_PATH);
		return errno;
	}

	rc = read(fsi_fd, &data, 4);
	if (rc < 0) {
		if ((addr64 & 0xfff) != 0xc09)
			/* We expect reads of 0xc09 to occasionally
			 * fail as the probing code uses it to see
			 * if anything is present on the link. */
			warn("Failed to read from 0x%08x (%016llx)", (uint32_t)addr, addr64);
		return errno;
	}

	*value = (uint64_t)swap_endian(data);

	return 0;
}

static int kernel_fsi_putcfam(struct target *target, uint64_t addr64, uint64_t data)
{
	int rc;
	uint32_t data32;
	uint32_t addr = (addr64 & 0x7ffc00) | ((addr64 & 0x3ff) << 2);

	rc = lseek(fsi_fd, addr, SEEK_SET);
	if (rc < 0) {
		warn("Failed to seek %s", FSI_CFAM_PATH);
		return errno;
	}

	data32 = swap_endian((uint32_t)data);

	rc = write(fsi_fd, &data32, 4);
	if (rc < 0) {
		warn("Failed to write to 0x%08x (%016llx)", addr, addr64);
		return errno;
	}

	return 0;
}

static void kernel_fsi_destroy(struct target *target)
{
	close(fsi_fd);
}

static void kernel_fsi_scan_devices(void)
{
	const char one = '1';
	int rc, fd;

	fd = open(FSI_SCAN_PATH, O_WRONLY | O_SYNC);
	if (fd < 0) {
		fd = open(FSI_SCAN_PATH_OLD, O_WRONLY | O_SYNC);
		if (fd < 0)
			err(errno, "Unable to open %s and %s", FSI_SCAN_PATH,
			    FSI_SCAN_PATH_OLD);

		swap_endian = kernel_fsi_no_swap_endian;
		fsi_old = 1;
	}

	rc = write(fd, &one, sizeof(one));
	if (rc < 0)
		err(errno, "Unable to write to %s",
		    fsi_old ? FSI_SCAN_PATH_OLD : FSI_SCAN_PATH);

	close(fd);
}

int kernel_fsi_target_init(struct target *target, const char *name,
			   struct target *next)
{
	uint64_t value;

	if (!fsi_fd) {
		int tries = NUM_TRIES_PROBE;

		while (tries) {
			/* Open first raw device */
			if (fsi_old) 
				fsi_fd = open(FSI_CFAM_PATH_OLD,
					      O_RDWR | O_SYNC);
			else {
				fsi_fd = open(FSI_CFAM_PATH, O_RDWR | O_SYNC);
				/* try old path if its the first try since
				 * we haven't set fsi_old yet
				 */
				if (fsi_fd < 0 && tries == NUM_TRIES_PROBE) {
					fsi_fd = open(FSI_CFAM_PATH_OLD,
						      O_RDWR | O_SYNC);

					if (fsi_fd >= 0) {
						fsi_old = 1;
						swap_endian = kernel_fsi_no_swap_endian;
						goto found;
					}
				}
			}

			if (fsi_fd >= 0)
				goto found;
			tries--;

			/* Scan */
			kernel_fsi_scan_devices();
			sleep(1);
		}
		if (fsi_fd < 0)
			err(errno, "Unable to open %s", FSI_CFAM_PATH);

	}
found:
	/* No cascaded devices after this one. */
	assert(next == NULL);
	target_init(target, name, 0, kernel_fsi_getcfam, kernel_fsi_putcfam,
		    kernel_fsi_destroy, next);

	/* Read chip id */
	CHECK_ERR(read_target(target, 0xc09, &value));
	target->chip_type = get_chip_type(value);

	return 0;
}

int kernel_fsi2pib_target_init(struct target *target, const char *name,
				uint64_t base, struct target *next)
{
	target_init(target, name, base, kernel_getscom, kernel_putscom, NULL,
			next);

	return 0;

}
