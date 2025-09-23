// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C), 2008-2021, OPPO Mobile Comm Corp., Ltd.
 * Created by Huang Jianan <huangjianan@oppo.com>
 */
#include <string.h>
#include <stdlib.h>
#include "erofs/err.h"
#include "erofs/list.h"
#include "erofs/print.h"
#include "erofs/compress_hints.h"

static LIST_HEAD(compress_hints_head);

static void dump_regerror(int errcode, const char *s, const regex_t *preg)
{
	char str[512];

	regerror(errcode, preg, str, sizeof(str));
	erofs_err("invalid regex %s (%s)\n", s, str);
}

/* algorithmtype is actually ccfg # here */
static int erofs_insert_compress_hints(const char *s, unsigned int blks,
				       unsigned int algorithmtype)
{
	struct erofs_compress_hints *ch;
	int ret;

	ch = malloc(sizeof(struct erofs_compress_hints));
	if (!ch)
		return -ENOMEM;

	ret = regcomp(&ch->reg, s, REG_EXTENDED|REG_NOSUB);
	if (ret) {
		dump_regerror(ret, s, &ch->reg);
		free(ch);
		return ret;
	}
	ch->physical_clusterblks = blks;
	ch->algorithmtype = algorithmtype;

	list_add_tail(&ch->list, &compress_hints_head);
	erofs_info("compress hint %s (%u) is inserted", s, blks);
	return ret;
}

bool z_erofs_apply_compress_hints(struct erofs_importer *im,
				  struct erofs_inode *inode)
{
	const struct erofs_importer_params *params = im->params;
	unsigned int pclusterblks = params->pclusterblks_def;
	unsigned int algorithmtype;
	struct erofs_compress_hints *r;
	const char *s;

	if (inode->z_physical_clusterblks)
		return true;

	s = erofs_fspath(inode->i_srcpath);
	algorithmtype = 0;

	list_for_each_entry(r, &compress_hints_head, list) {
		int ret = regexec(&r->reg, s, (size_t)0, NULL, 0);

		if (!ret) {
			pclusterblks = r->physical_clusterblks;
			algorithmtype = r->algorithmtype;
			break;
		}
		if (ret != REG_NOMATCH)
			dump_regerror(ret, s, &r->reg);
	}
	inode->z_physical_clusterblks = pclusterblks;
	inode->z_algorithmtype[0] = algorithmtype;

	/* pclusterblks is 0 means this file shouldn't be compressed */
	return pclusterblks != 0;
}

void erofs_cleanup_compress_hints(void)
{
	struct erofs_compress_hints *r, *n;

	list_for_each_entry_safe(r, n, &compress_hints_head, list) {
		list_del(&r->list);
		free(r);
	}
}

int erofs_load_compress_hints(struct erofs_importer *im,
			      struct erofs_sb_info *sbi)
{
	struct erofs_importer_params *params = im->params;
	char buf[PATH_MAX + 100];
	FILE *f;
	unsigned int line, max_pclusterblks = 0;
	int ret = 0;

	if (!cfg.c_compress_hints_file)
		return 0;

	f = fopen(cfg.c_compress_hints_file, "r");
	if (!f)
		return -errno;

	for (line = 1; fgets(buf, sizeof(buf), f); ++line) {
		unsigned int pclustersize, pclusterblks, ccfg;
		char *alg, *pattern;

		if (*buf == '#' || *buf == '\n')
			continue;

		pclustersize = atoi(strtok(buf, "\t "));
		alg = strtok(NULL, "\n\t ");
		pattern = strtok(NULL, "\n");
		if (!pattern) {
			pattern = alg;
			alg = NULL;
		}
		if (!pattern || *pattern == '\0') {
			erofs_err("cannot find a match pattern at line %u",
				  line);
			ret = -EINVAL;
			goto out;
		}
		if (!alg || *alg == '\0') {
			ccfg = 0;
		} else {
			ccfg = atoi(alg);
			if (ccfg >= EROFS_MAX_COMPR_CFGS ||
			    !cfg.c_compr_opts[ccfg].alg) {
				erofs_err("invalid compressing configuration \"%s\" at line %u",
					  alg, line);
				ret = -EINVAL;
				goto out;
			}
		}

		if (pclustersize % erofs_blksiz(sbi)) {
			erofs_warn("invalid physical clustersize %u, use default pclustersize (%u blocks)",
				   pclustersize, params->pclusterblks_max);
			continue;
		}
		pclusterblks = pclustersize >> sbi->blkszbits;
		erofs_insert_compress_hints(pattern, pclusterblks, ccfg);

		if (pclusterblks > max_pclusterblks)
			max_pclusterblks = pclusterblks;
	}

	if (params->pclusterblks_max < max_pclusterblks) {
		erofs_warn("update max pclustersize to %u blocks",
			   max_pclusterblks);
		params->pclusterblks_max = max_pclusterblks;
	}
out:
	fclose(f);
	return ret;
}
