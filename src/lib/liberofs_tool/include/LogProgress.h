#pragma once

#include <atomic>
#include <string>
#include <unistd.h>

namespace skkk::erofs {
	static void progress(const char *tagPrefixFmt, uint64_t totalSize, uint64_t index, int perPrint, bool hasEnter) {
		if (index % perPrint == 0 || index == totalSize) {
			const float percentage = static_cast<float>(index) / static_cast<float>(totalSize) * 100.0F;
			printf(tagPrefixFmt, percentage);
			if (hasEnter && percentage == 100) [[unlikely]] {
				printf("\n");
			}
		}
	}

	static void progressMT(const char *tagPrefix, uint64_t totalSize, const std::atomic_int &progress, bool hasEnter) {
		uint32_t currProgress = 0;
		float previousPercentage = 0, percentage = 0;
		do {
			if (currProgress != progress) {
				percentage = static_cast<float>(progress) / static_cast<float>(totalSize) * 100.0F;
				if (percentage > previousPercentage) {
					printf(tagPrefix, percentage);
					if (hasEnter && percentage == 100) [[unlikely]] {
						printf("\n");
					}
					previousPercentage = percentage;
				}
				currProgress = progress;
				sleep(0);
			}
			sleep(0);
		} while (currProgress != totalSize);
	}
}
