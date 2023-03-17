// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2023 skkk
 */

#include <getopt.h>
#include <erofs/io.h>
#include <erofs/config.h>
#include <erofs/print.h>
#include <sys/time.h>

#include "ExtractState.h"
#include "ExtractOperation.h"
#include "Logging.h"

using namespace skkk;

static void usage() {
	char buf[1024] = {0};
	snprintf(buf, 1024,
			 BROWN "usage: [options]" COLOR_NONE "\n"
			 "  " GREEN2_BOLD "-h, --help" COLOR_NONE "          " BROWN "Display this help and exit" COLOR_NONE "\n"
			 "  " GREEN2_BOLD "-i, --image=[FILE]" COLOR_NONE "  " BROWN "Image file" COLOR_NONE "\n"
			 "  " GREEN2_BOLD "-p" COLOR_NONE "                  " BROWN "Print all entrys" COLOR_NONE "\n"
			 "  " GREEN2_BOLD "--print=X" COLOR_NONE "           " BROWN "Print the target of path X" COLOR_NONE "\n"
			 "  " GREEN2_BOLD "-x" COLOR_NONE "                  " BROWN "Extract all items" COLOR_NONE "\n"
			 "  " GREEN2_BOLD "--extract=X" COLOR_NONE "         " BROWN "Extract the target of path X" COLOR_NONE "\n"
			 "  " GREEN2_BOLD "-f, --overwrite" COLOR_NONE "     " BROWN "[" GREEN2_BOLD "default: skip" COLOR_NONE BROWN "] overwrite files that already exist" COLOR_NONE "\n"
			 "  " GREEN2_BOLD "-T#" COLOR_NONE "                 " BROWN "[" GREEN2_BOLD "1-%u" COLOR_NONE BROWN "] Use # threads, -T0: " GREEN2_BOLD "%u" COLOR_NONE COLOR_NONE "\n"
			 "  " GREEN2_BOLD "--only-cfg" COLOR_NONE "          " BROWN "Only extract fs_config and file_contexts" COLOR_NONE "\n"
			 "  " GREEN2_BOLD "-o, --outdir=X" COLOR_NONE "      " BROWN "Output dir" COLOR_NONE "\n"
			 "  " GREEN2_BOLD "-V, --version" COLOR_NONE "       " BROWN "Print the version info" COLOR_NONE "\n",
			 eo->limitHardwareConcurrency,
			 eo->hardwareConcurrency
	);
	fputs(buf, stderr);
}

static inline void print_version() {
	printf("  " BROWN "extract.erofs:" COLOR_NONE "      " RED2_BOLD "1.0.2" COLOR_NONE "\n");
	printf("  " BROWN "Author:" COLOR_NONE "             " RED2_BOLD "skkk" COLOR_NONE "\n");
}

static struct option arg_options[] = {
		{"help",      no_argument,       nullptr, 'h'},
		{"version",   no_argument,       nullptr, 'V'},
		{"image",     required_argument, nullptr, 'i'},
		{"outdir",    required_argument, nullptr, 'o'},
		{"print",     required_argument, nullptr, 'P'},
		{"extract",   required_argument, nullptr, 'X'},
		{"overwrite", no_argument,       nullptr, 'f'},
		{"only-cfg",  no_argument,       nullptr, 1},
		{nullptr,     no_argument,       nullptr, 0},
};

static int parseAndCheckExtractCfg(int argc, char **argv) {
	int opt;
	int rc = RET_EXTRACT_CONFIG_FAIL;
	bool enterParseOpt = false;
	while ((opt = getopt_long(argc, argv, "hi:pxfT:o:V", arg_options, nullptr)) != -1) {
		enterParseOpt = true;
		switch (opt) {
			case 'h':
				usage();
				goto exit;
			case 'V':
				print_version();
				goto exit;
			case 'i':
				if (optarg) {
					eo->setImgPath(optarg);
				}
				LOGCD("imgPath=%s", eo->getImgPath().c_str());
				break;
			case 'o':
				if (optarg) {
					eo->setOutDir(optarg);
				}
				LOGCD("outDir=%s", eo->getOutDir().c_str());
				break;
			case 'p':
				eo->isPrintAllNode = true;
				LOGCD("isPrintAllNode=%d", eo->isPrintAllNode);
				break;
			case 'P':
				eo->isPrintTarget = true;
				if (optarg) eo->targetPath = optarg;
				LOGCD("isPrintTarget=%d targetPath=%s", eo->isPrintTarget, eo->targetPath.c_str());
				break;
			case 'x':
				eo->check_decomp = true;
				eo->isExtractAllNode = true;
				LOGCD("isExtractAllNode=%d check_decomp=%d", eo->isExtractAllNode, eo->check_decomp);
				break;
			case 'X':
				eo->check_decomp = true;
				eo->isExtractTarget = true;
				if (optarg) eo->targetPath = optarg;
				LOGCD("isExtractTarget=%d targetPath=%s", eo->isExtractTarget, eo->targetPath.c_str());
				break;
			case 'f':
				eo->overwrite = true;
				LOGCD("overwrite=%d", eo->overwrite);
				break;
			case 'T':
				eo->useMultiThread = true;
				if (optarg) {
					unsigned int n = strtoul(optarg, nullptr, 10);
					if (n > 0) {
						eo->threadNum = n;
					}
				}
				break;
			case 1:
				eo->extractOnlyConfAndSeLabel = true;
				LOGCD("extractOnlyConfAndSeLabel=%d", eo->extractOnlyConfAndSeLabel);
				break;
			default:
				usage();
				print_version();
				goto exit;
		}
	}

	if (enterParseOpt) {
		bool err;
		// check needed arg
		err = !eo->getImgPath().empty() && fileExists(eo->getImgPath());
		if (!err) {
			LOGCE("img file '%s' does not exist", eo->getImgPath().c_str());
			goto exit;
		}
		rc = !eo->initOutDir();
		if (!rc) {
			goto exit;
		}
		LOGCD("outDir=%s confDir=%s", eo->getOutDir().c_str(), eo->getConfDir().c_str());

		if (eo->useMultiThread) {
			if (eo->threadNum > eo->limitHardwareConcurrency) {
				rc = RET_EXTRACT_THREAD_NUM_ERROR;
				LOGCE("Threads min: 1 , max: %u", eo->limitHardwareConcurrency);
				goto exit;
			} else if (eo->threadNum == 0) {
				eo->threadNum = eo->hardwareConcurrency;
			}
			LOGCD("Threads num=%u", eo->threadNum);
		}
		rc = RET_EXTRACT_CONFIG_DONE;
	} else {
		usage();
	}

exit:
	return rc;
}

static inline void printOperationTime(struct timeval *start, struct timeval *end) {
	LOGCI(GREEN2_BOLD "The operation took: " COLOR_NONE RED2 "%.3f" COLOR_NONE "%s",
		  (end->tv_sec - start->tv_sec) + (float) (end->tv_usec - start->tv_usec) / 1000000,
		  GREEN2_BOLD " second(s)." COLOR_NONE
	);
}

int main(int argc, char **argv) {
	int ret = RET_EXTRACT_DONE, err;

	struct timeval start = {}, end = {};
	// Start time
	gettimeofday(&start, nullptr);

	// Initialize erofs config
	erofs_init_configure();
	cfg.c_dbg_lvl = EROFS_ERR;

	// Initialize extract config
	err = parseAndCheckExtractCfg(argc, argv);
	if (err != RET_EXTRACT_CONFIG_DONE) {
		ret = err;
		goto exit;
	}

	err = dev_open_ro(eo->getImgPath().c_str());
	if (err) {
		ret = RET_EXTRACT_INIT_FAIL;
		LOGCE("failed to open '%s'", eo->getImgPath().c_str());
		goto exit;
	}

	err = erofs_read_superblock();
	if (err) {
		ret = RET_EXTRACT_INIT_FAIL;
		LOGCE("failed to read superblock");
		goto exit_dev_close;
	}

	if (eo->isPrintTarget || eo->isExtractTarget)
		err = eo->initErofsNodeByTarget();
	else if (eo->isPrintAllNode || eo->isExtractAllNode)
		err = eo->initAllErofsNode();
	if (err) {
		ret = RET_EXTRACT_INIT_NODE_FAIL;
		goto exit_dev_close;
	}

	if (eo->isPrintTarget || eo->isPrintAllNode) {
		ExtractOperation::printInitializedNode();
		goto exit_dev_close;
	}

	LOGCI(GREEN2_BOLD "Starting..." COLOR_NONE);

	if ((eo->isExtractTarget || eo->isExtractAllNode) && eo->extractOnlyConfAndSeLabel) {
		err = eo->createExtractConfigDir();
		if (err) {
			ret = RET_EXTRACT_CREATE_DIR_FAIL;
			goto exit_dev_close;
		}
		eo->extractFsConfigAndSeLabel();
		goto end;
	}

	if (eo->isExtractTarget || eo->isExtractAllNode) {
		err = eo->createExtractConfigDir() && eo->createExtractOutDir();
		if (err) {
			ret = RET_EXTRACT_CREATE_DIR_FAIL;
			goto exit_dev_close;
		}
		eo->extractFsConfigAndSeLabel();
		eo->useMultiThread ? eo->extractErofsNodeMultiThread() : eo->extractErofsNode();
		goto end;
	}

end:
	// End time
	gettimeofday(&end, nullptr);
	printOperationTime(&start, &end);

exit_dev_close:
	dev_close();
	LOGCD("ErofsNode size=%lu", eo->getErofsNodes().size());
	LOGCD("main exit ret=%d", ret);

exit:
	blob_closeall();
	erofs_exit_configure();
	ExtractOperation::erofsOperationExit();
	return ret;
}
