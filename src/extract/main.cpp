// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2026 skkk
 */

#include <getopt.h>
#include <memory>
#include <print>
#include <string>
#include <sys/time.h>

#include <compressor.h>
#include <erofs/config.h>
#include <erofs/ErofsParser.h>
#include <erofs/ExtractConfig.h>
#include <erofs/internal.h>
#include <LogBase.h>

#include "ExtractOperation.h"

using namespace skkk::erofs;

static void get_available_compressors(std::string &ret) {
	int i = 0;
	bool comma = false;
	const erofs_algorithm *s;

	while ((s = z_erofs_list_available_compressors(&i)) != nullptr) {
		if (comma)
			ret.append(", ");
		ret.append(s->name);
		comma = true;
	}
}

static void usage(const ExtractConfig &eo) {
	char buf[4096] = {};
	// @formatter:off
	snprintf(buf, sizeof(buf) - 1,
			 BROWN( "usage: [options]") "\n"
			 "  " GREEN2_BOLD("-h, --help") "              " BROWN("Display this help and exit") "\n"
			 "  " GREEN2_BOLD("-i, --image=[FILE]") "      " BROWN("Image file") "\n"
			 "  " GREEN2_BOLD("--offset=#") "              " BROWN("skip # bytes at the beginning of IMAGE") "\n"
			 "  " GREEN2_BOLD("-p") "                      " BROWN("Print all entrys") "\n"
			 "  " GREEN2_BOLD("-P, --print=X") "           " BROWN("Print the target of path X") "\n"
			 "  " GREEN2_BOLD("-x") "                      " BROWN("Extract all items" ) "\n"
			 "  " GREEN2_BOLD("-X, --extract=X") "         " BROWN("Extract the target of path X") "\n"
			 "  " GREEN2_BOLD("-c, --config=[FILE]") "     " BROWN("Target of config") "\n"
			 "  " GREEN2_BOLD("-r") "                      " BROWN("When using config, recurse directories") "\n"
			 "  " GREEN2_BOLD("-s") "                      " BROWN("Silent mode, Don't show progress") "\n"
			 "  " GREEN2_BOLD("-f, --overwrite") "         " BROWN("[") GREEN2_BOLD("default: skip") BROWN("] overwrite files that already exist") "\n"
			 "  " GREEN2_BOLD("-T#") "                     " BROWN("[") GREEN2_BOLD("1-%u") BROWN("] Use # threads, default: -T0, is ") GREEN2_BOLD("%u") "\n"
			 "  " GREEN2_BOLD("--only-cfg") "              " BROWN("Only extract fs_config|file_contexts|fs_options")"\n"
			 "  " GREEN2_BOLD("-o, --outdir=X") "          " BROWN("Output dir") "\n"
			 "  " GREEN2_BOLD("-V, --version") "           " BROWN("Print the version info") "\n",
			 eo.limitHardwareConcurrency,
			 eo.hardwareConcurrency
	);
	// @formatter:on
	std::println("{}", buf);
}

#ifndef EROFS_EXTRACT_VERSION
#define EROFS_EXTRACT_VERSION "v0.0.0"
#endif
#ifndef EROFS_EXTRACT_BUILD_TIME
#define EROFS_EXTRACT_BUILD_TIME "-0000000000"
#endif

static void print_version() {
	std::string compressors;
	get_available_compressors(compressors);
	printf("  " BROWN("erofs-utils:") "            " RED2_BOLD("%s") "\n", erofs_get_configure()->c_version);
	printf("  " BROWN("extract.erofs:") "          " RED2_BOLD(EROFS_EXTRACT_VERSION EROFS_EXTRACT_BUILD_TIME) "\n");
	printf("  " BROWN("available compressors:") "  " RED2_BOLD("%s") "\n", compressors.c_str());
	printf("  " BROWN("extract author:") "         " RED2_BOLD("skkk") "\n");
}

static option arg_options[] = {
	{"help", no_argument, nullptr, 'h'},
	{"version", no_argument, nullptr, 'V'},
	{"image", required_argument, nullptr, 'i'},
	{"offset", required_argument, nullptr, 2},
	{"outdir", required_argument, nullptr, 'o'},
	{"print", required_argument, nullptr, 'P'},
	{"overwrite", no_argument, nullptr, 'f'},
	{"extract", required_argument, nullptr, 'X'},
	{"config", required_argument, nullptr, 'c'},
	{"only-cfg", no_argument, nullptr, 1},
	{nullptr, no_argument, nullptr, 0},
};

static int parseExtractConfig(int argc, char **argv, ExtractOperation &eo) {
	int opt, ret = RET_EXTRACT_CONFIG_FAIL;
	bool enterCheckOpt = false;
	while ((opt = getopt_long(argc, argv, "hi:psxfrc:P:T:o:X:V", arg_options, nullptr)) != -1) {
		enterCheckOpt = true;
		switch (opt) {
			case 'h':
				usage(eo);
				goto exit;
			case 'V':
				print_version();
				goto exit;
			case 'i':
				if (optarg) {
					eo.setImagePath(optarg);
				}
				LOGCD("imagePath={}", eo.getImagePath());
				break;
			case 'o':
				if (optarg) {
					eo.setOutDir(optarg);
				}
				LOGCD("outDir={}", eo.getOutDir());
				break;
			case 'p':
				eo.isPrintAll = true;
				LOGCD("isPrintAll={}", eo.isPrintAll);
				break;
			case 'P':
				eo.isPrintTarget = true;
				if (optarg) eo.setTargets(optarg);
				LOGCD("isPrintTarget={} targets={}", eo.isPrintTarget, eo.getTargets());
				break;
			case 'f':
				eo.overwrite = true;
				LOGCD("overwrite={}", eo.overwrite);
				break;
			case 'x':
				eo.check_decomp = true;
				eo.isExtractAll = true;
				LOGCD("isExtractAll={} check_decomp={}", eo.isExtractAll, eo.check_decomp);
				break;
			case 'X':
				eo.check_decomp = true;
				eo.isExtractTarget = true;
				if (optarg) eo.setTargets(optarg);
				LOGCI("isExtractTarget={} targetPath={}", eo.isExtractTarget, eo.getTargets());
				break;
			case 'c':
				eo.isExtractTargetConfig = true;
				if (optarg) eo.setTargetConfigPath(optarg);
				LOGCD("targetConfig={}", eo.getTargetConfigPath());
				break;
			case 's':
				eo.isSilent = true;
				LOGCD("isSilent={}", eo.isSilent);
				break;
			case 'r':
				eo.targetRecursive = true;
				LOGCD("targetConfigRecursive={}", eo.targetRecursive);
				break;
			case 'T':
				if (optarg) {
					char *endPtr;
					uint64_t n = strtoull(optarg, &endPtr, 0);
					if (*endPtr == '\0') {
						eo.threadNum = n;
					}
				}
				break;
			case 1:
				eo.isExtractConfig = true;
				LOGCD("isExtractConfig={}", eo.isExtractConfig);
				break;
			case 2:
				if (optarg) {
					char *endPtr;
					uint64_t n = strtoull(optarg, &endPtr, 0);
					if (*endPtr == '\0') {
						eo.setOffset(n);
						LOGCD("offset={}", eo.getOffset());
					}
				}
				break;
			default:
				usage(eo);
				print_version();
				goto exit;
		}
	}

	if (enterCheckOpt) {
		if (eo.getImagePath().empty()) {
			ret = RET_EXTRACT_OPEN_FILE;
			goto exit;
		}

		ret = eo.initOutDir();
		if (ret) goto exit;

		if (eo.threadNum > eo.limitHardwareConcurrency) {
			ret = RET_EXTRACT_THREAD_NUM_ERROR;
			LOGCE("Threads min: 1 , max: {}", eo.limitHardwareConcurrency);
			goto exit;
		}
		if (eo.threadNum == 0) {
			eo.threadNum = eo.hardwareConcurrency;
		}
		LOGCD("Threads num={}", eo.threadNum);
		ret = RET_EXTRACT_CONFIG_DONE;
	} else {
		usage(eo);
	}

exit:
	return ret;
}

static void printOperationTime(const timeval *start, const timeval *end) {
	LOGCI(GREEN2_BOLD("The operation took: ") RED2("{:.3f}") "{}",
	      (end->tv_sec - start->tv_sec) + static_cast<float>(end->tv_usec - start->tv_usec) / 1000000,
	      GREEN2_BOLD(" second(s).")
	);
}

int main(const int argc, char *argv[]) {
	int ret = RET_EXTRACT_DONE;
	bool err = false;
	timeval start{}, end{};

	setbuf(stdout, nullptr);
	setbuf(stderr, nullptr);

	LOG_TAG("Extract");

	// Start time
	gettimeofday(&start, nullptr);

	// Config
	erofs_init_configure();
	ExtractOperation eo;
	ErofsParser erofsParser;
	std::shared_ptr<ErofsWriter> ew;
	if (parseExtractConfig(argc, argv, eo) != RET_EXTRACT_CONFIG_DONE) {
		ret = RET_EXTRACT_INIT_FAIL;
		goto exit;
	}

	// Parse erofs image
	if (!erofsParser.parse(eo)) {
		ret = RET_EXTRACT_INIT_FAIL;
		goto exit;
	}

	// PartitionWriter
	ew = erofsParser.getErofsWriter();
	if (!ew) {
		ret = RET_EXTRACT_INIT_FAIL;
		goto exit;
	}

	if (eo.isPrintTarget || eo.isExtractTarget || eo.isExtractTargetConfig)
		err = ew->initErofsNodeByTarget();
	else if (eo.isPrintAll || eo.isExtractAll)
		err = ew->initErofsNode();
	if (!err) {
		ret = RET_EXTRACT_INIT_NODE_FAIL;
		goto exit;
	}

	if (eo.isPrintTarget || eo.isPrintAll) {
		ew->printInitializedNode();
		goto exit;
	}

	LOGCI(GREEN2_BOLD("Starting..."));

	if ((eo.isExtractTarget || eo.isExtractAll) && eo.isExtractConfig) {
		err = eo.createExtractConfigDir();
		if (err) {
			ret = RET_EXTRACT_CREATE_DIR_FAIL;
			goto exit;
		}
		ew->writeFsConfigAndSelinuxLabel();
		goto end;
	}

	if (eo.isExtractTarget || eo.isExtractAll) {
		err = eo.createExtractConfigDir() & eo.createExtractOutDir();
		if (err) {
			ret = RET_EXTRACT_CREATE_DIR_FAIL;
			goto exit;
		}
		ew->writeFsConfigAndSelinuxLabel();
		if (eo.threadNum == 1) {
			ew->extract();
		} else {
			ew->extractByMT();
		}
		goto end;
	}

end:
	// End time
	gettimeofday(&end, nullptr);
	printOperationTime(&start, &end);

exit:
	erofs_exit_configure();
	return ret;
}
