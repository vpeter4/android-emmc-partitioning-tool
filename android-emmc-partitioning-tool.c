/*
 * Simple partitioning tool for changing Android partitions
 *
 * Copyright (C) 2019 vpeter
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#include <stdio.h>
#include <stdarg.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define STORE_CODE         1
#define STORE_CACHE       (1 << 1)
#define STORE_DATA        (1 << 2)

#define     MAX_PART_NAME_LEN               16
#define     MAX_MMC_PART_NUM                32

/* MMC Partition Table */
#define     MMC_PARTITIONS_MAGIC            "MPT"
#define     MMC_RESERVED_NAME               "reserved"

#define     SZ_1M                           0x00100000

/* the size of bootloader partition */
#define     MMC_BOOT_PARTITION_SIZE         (4*SZ_1M)

/* the size of reserve space behind bootloader partition */
#define     MMC_BOOT_PARTITION_RESERVED     (32*SZ_1M)

#define     RESULT_OK                       0
#define     RESULT_FAIL                     1
#define     RESULT_UNSUP_HOST               2
#define     RESULT_UNSUP_CARD               3

struct __attribute__((__packed__)) partitions {
  /* identifier string */
  char name[MAX_PART_NAME_LEN];
  /* partition size, byte unit */
  uint64_t size;
  /* offset within the master space, byte unit */
  uint64_t offset;
  /* master flags to mask out for this partition */
  uint64_t mask_flags;
};

struct __attribute__((__packed__)) mmc_partitions_fmt {
  char magic[4];
  unsigned char version[12];
  uint32_t part_num;
  uint32_t checksum;
  struct partitions partitions[MAX_MMC_PART_NUM];
};

/* where reserved partition starts */
#define RESERVED_PARTITION_OFF \
  (MMC_BOOT_PARTITION_SIZE + MMC_BOOT_PARTITION_RESERVED)

static char get_key_input(void) {
char ch;

  ch = getchar();
  if (ch == '\n')
    return 0;

  /* rest of the characters */
  while(getchar() != '\n');

  return tolower(ch);
}
/*
static int get_reserve_partition_off_from_tbl(
  struct mmc_partitions_fmt *pt_fmt
)
{
  int i;

  for (i = 0; i < pt_fmt->part_num; i++) {
    if (!strcmp(pt_fmt->partitions[i].name, MMC_RESERVED_NAME))
      return pt_fmt->partitions[i].offset;
  }
  return -1;
}
*/
static int mmc_partition_tbl_checksum_calc(
    struct partitions *part, int part_num)
{
  int i, j;
  uint32_t checksum = 0, *p;

  for (i = 0; i < part_num; i++) {
    p = (uint32_t *)part;

    for (j = sizeof(struct partitions)/sizeof(checksum);
        j > 0; j--) {
      checksum += *p;
      p++;
    }
  }

  return checksum;
}

static char *mask_flags_str(uint32_t mask_flags) {
  switch(mask_flags) {
    case STORE_CODE:
      return "code";
    case STORE_CACHE:
      return "cache";
    case STORE_DATA:
      return "data";
    default:
      return "unkn";
  }
}

static int read_partition_table(
  struct mmc_partitions_fmt **pt_fmt,
  char *file,
  size_t offset
) {
FILE *fp;

  *pt_fmt = calloc(1, sizeof(struct mmc_partitions_fmt));
  if (pt_fmt == NULL) {
    printf("malloc failed for struct mmc_partitions_fmt!\n");
    return -1;
  }

  fp = fopen(file, "rb");
  if (fp == NULL) {
    printf("Error opening file for reading '%s'!\n", file);
    return -1;
  }

  if (fseek(fp, offset, SEEK_SET) != 0) {
    printf("Error seek file!\n");
    fclose(fp);
    return -1;
  }

  if (fread(*pt_fmt, sizeof(struct mmc_partitions_fmt), 1, fp) != 1) {
    printf("Error reading file!\n");
    fclose(fp);
    return -1;
  }

  fclose(fp);
  return 0;
}


static int write_partition_table(
  struct mmc_partitions_fmt *pt_fmt,
  char *file,
  size_t offset
) {
FILE *fp;

  fp = fopen(file, "rb+");
  if (fp == NULL) {
    printf("Error opening file for writing '%s'!\n", file);
    return -1;
  }

  if (fseek(fp, offset, SEEK_SET) != 0) {
    printf("Error seek file!\n");
    fclose(fp);
    return -1;
  }

  if (fwrite(pt_fmt, sizeof(struct mmc_partitions_fmt), 1, fp) != 1) {
    printf("Error writing file!\n");
    fclose(fp);
    return -1;
  }

  fclose(fp);
  return 0;
}

static int show_partition_table(
  struct mmc_partitions_fmt *pt_fmt,
  unsigned int first
) {
unsigned int i;
uint64_t offset, size;
struct partitions *pp;
int ret;

  printf("partition magic: '%s'\n", pt_fmt->magic);
  printf("        version: '%s'\n", pt_fmt->version);
  printf("         number: %d\n",   pt_fmt->part_num);
  printf("       checksum: %#x\n",  pt_fmt->checksum);
  printf("\n");

  if ((strncmp(pt_fmt->magic, MMC_PARTITIONS_MAGIC,
        sizeof(pt_fmt->magic)) == 0) /* the same */
      && (pt_fmt->part_num > 0)
      && (pt_fmt->part_num <= MAX_MMC_PART_NUM)
      && (pt_fmt->checksum ==
        mmc_partition_tbl_checksum_calc(
          pt_fmt->partitions,
          pt_fmt->part_num))) {
    ret = 0; /* everything is OK now */
  } else {
    if (strncmp(pt_fmt->magic, MMC_PARTITIONS_MAGIC,
          sizeof(pt_fmt->magic)) != 0) {
      printf("magic error: %s\n",
          (pt_fmt->magic)?pt_fmt->magic:"NULL");
    } else if ((pt_fmt->part_num < 0)
        || (pt_fmt->part_num > MAX_MMC_PART_NUM)) {
      printf("partition number error: %d\n",
          pt_fmt->part_num);
    } else {
      printf(
        "checksum error: pt_fmt->checksum=%#x,calc_result=%#x\n",
        pt_fmt->checksum,
        mmc_partition_tbl_checksum_calc(
          pt_fmt->partitions,
          pt_fmt->part_num));
    }

    printf("partition verified error\n");
    ret = -1; /* the partition information is invalid */
  }

  if (ret != 0) {
    return -1;
  }

  first--;  /* starts with 1 */
  if (first < 0)
    first = 0;

  for (i = first; i < pt_fmt->part_num && i < MAX_MMC_PART_NUM; i++) {
    pp = &(pt_fmt->partitions[i]);
    offset = pp->offset;
    size = pp->size;
    printf("[mmcblk0p%02d] %20s  offset 0x%012llx, size 0x%012llx [%" PRIu64 " MB], %s\n",
          i+1, pp->name, (long long unsigned int) offset,
          (long long unsigned int) size,
          size / (1024 * 1024),
          mask_flags_str(pp->mask_flags));
  }

  return 0;
}

static int modify_partition_table(
  struct mmc_partitions_fmt *pt_fmt
) {
struct partitions *pp;
uint64_t size_system_storage;
uint64_t last_offset;
unsigned int i;

  /* complete size of last 3 partitions */
  size_system_storage = pt_fmt->partitions[18 - 1].size +
                        pt_fmt->partitions[19 - 1].size +
                        pt_fmt->partitions[20 - 1].size;

  printf("size_system_storage: %d MB\n", (int) (size_system_storage / (1024 * 1024)));

  /* ce SYSTEM partition */
  pp = &(pt_fmt->partitions[18 - 1]);
  strncpy(pp->name, "ce_system", MAX_PART_NAME_LEN);
  pp->name[MAX_PART_NAME_LEN-1] = 0;
  pp->mask_flags = STORE_DATA;
  //pp->mask_flags = STORE_CODE;
  pp->size = 512UL * SZ_1M;
  
  last_offset = pp->offset + pp->size;

  /* remaining for storage */
  size_system_storage -= pp->size;

  /* TODO: check available size */

  /* ce STORAGE partition, combine last 2 partitions */
  pp = &(pt_fmt->partitions[19 - 1]);
  strncpy(pp->name, "ce_storage", MAX_PART_NAME_LEN);
  /* last partition must be named data ! ??? */
  /* strncpy(pp->name, "data", MAX_PART_NAME_LEN); */
  pp->name[MAX_PART_NAME_LEN-1] = 0;
  pp->mask_flags = STORE_DATA;
  
  pp->offset = last_offset;
  //pp->size = size_system_storage;
  pp->size = SZ_1M * (uint64_t) 10000;

  /* new number of partitions */
  pt_fmt->part_num = 19;

  /* clean unused partitions (better visual compare) */
  for (i = pt_fmt->part_num; i < MAX_MMC_PART_NUM; i++)
    memset(&(pt_fmt->partitions[i]), 0, sizeof(struct partitions));

  /* fix checksum */
  pt_fmt->checksum = mmc_partition_tbl_checksum_calc(
    pt_fmt->partitions, pt_fmt->part_num);

  return 0;
}

int main(int argc, char **argv) {
char *input_file;
size_t input_offset;
struct mmc_partitions_fmt *pt_fmt = NULL;

  printf("\nStarting Generic eMMC partitioning tool v0.1...\n\n");

  if (argc < 2) {
    printf("  Usage: %s input_file\n\n", argv[0]);
    return -1;
  }

  input_file = argv[1];

  if (argc == 3)
    input_offset = (size_t) argv[2];
  else
    input_offset = RESERVED_PARTITION_OFF;

  printf(" sizeof partitions format: %d B\n",
    (int) sizeof(struct mmc_partitions_fmt));

  printf("reserved partition offset: 0x%012x [%d MB]\n",
    (unsigned int) input_offset, (int) (input_offset / (1024 * 1024)));

  if (read_partition_table(&pt_fmt, input_file, input_offset) != 0) {
    return -1;
  }

  printf("\nOriginal partition table:\n");
  if (show_partition_table(pt_fmt, 1) != 0) {
    return -1;
  }

  printf("\nChange partitions. Continue? [y/N]: ");
  if (get_key_input() != 'y') {
    printf("\nAborting!\n\n");
    return 0;
  }

  if (modify_partition_table(pt_fmt) != 0) {
    return -1;
  }

  printf("\nChanged partition table:\n");
  if (show_partition_table(pt_fmt, 18) != 0) {
    return -1;
  }

  printf("\nWrite new partition table. Continue? [y/N]: ");
  if (get_key_input() != 'y') {
    printf("\nAborting!\n\n");
    return 0;
  }

  if (write_partition_table(pt_fmt, input_file, input_offset) != 0) {
    return -1;
  }

  printf("\nSuccess!\n\n");
  return 0;
}
