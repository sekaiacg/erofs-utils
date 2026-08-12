#pragma once

#include <cstdint>
#include <cstring>
#include <functional>
#include <format>
#include <print>
#include <source_location>

/**
 * Reference：https://github.com/archibate/minilog
 */
namespace minilog {
#define MINILOG_FOREACH_LOG_LEVEL(f) \
	f(verbose) \
	f(debug) \
	f(info) \
	f(warn) \
	f(error)

	enum class log_level : std::uint8_t {
#define _FUNCTION(name) name,
		MINILOG_FOREACH_LOG_LEVEL(_FUNCTION)
#undef _FUNCTION
	};

	namespace details {
#define _MINILOG_IF_HAS_ANSI_COLORS(x) x
		inline constexpr char k_level_ansi_colors[static_cast<std::uint8_t>(log_level::error) + 1][8] = {
			"\E[94;1m",
			"\E[94;1m",
			"\E[93;1m",
			"\E[93;1m",
			"\E[91;1m",
		};
		inline constexpr char k_reset_ansi_color[4] = "\E[m";

		inline std::string log_level_name(const log_level &lev) {
			switch (lev) {
#define _FUNCTION(name) case log_level::name: return #name;
				MINILOG_FOREACH_LOG_LEVEL(_FUNCTION)
#undef _FUNCTION
			}
			return "unknown";
		}

		inline log_level log_level_from_name(const std::string &lev) {
#define _FUNCTION(name) if (lev == #name) return log_level::name;
			MINILOG_FOREACH_LOG_LEVEL(_FUNCTION)
#undef _FUNCTION
			return log_level::error;
		}

		template<class T>
		struct with_source_location {
			private:
				T inner;
				std::source_location loc;

			public:
				template<class U> requires std::constructible_from<T, U>
				consteval with_source_location(U &&inner, std::source_location loc = std::source_location::current())
					: inner(std::forward<U>(inner)), loc(std::move(loc)) {
				}

				constexpr T const &format() const { return inner; }
				constexpr std::source_location const &location() const { return loc; }
		};


		inline std::string g_log_tag = []() -> std::string {
			if (auto tag = std::getenv("MINILOG_TAG")) {
				return std::format("{}: ", tag);
			}
			return "ETOOL: ";
		}();

		inline log_level g_max_level = []() -> log_level {
			if (auto lev = std::getenv("MINILOG_LEVEL")) {
				return details::log_level_from_name(lev);
			}
			return log_level::verbose;
		}();

		inline const char *handleFilePath(std::source_location const &loc) {
			auto *p = loc.file_name();
			if (auto *result = strrchr(p, '/')) {
				p += result - p + 1;
			}
			return p;
		}

		inline std::string handleFuncName(std::source_location const &loc) {
			std::string result{loc.function_name()};
			auto endPos = result.find_first_of('(');
			if (endPos != std::string::npos) {
				auto startPos = result.find_last_of(':', endPos);
				if (startPos == std::string::npos) {
					startPos = result.find_last_of(' ', endPos);
				}
				if (startPos != std::string::npos) {
					result = std::move(result.substr(startPos + 1, endPos - startPos - 1));
				}
			}
			return result;
		}

		inline void init_log_msg(const log_level &lev, std::string &msg, std::source_location const &loc) {
			if (lev <= log_level::debug) {
				msg = std::format("{}{}:{}:{}, {}", g_log_tag, std::move(handleFuncName(loc)), handleFilePath(loc),
				                  loc.line(),
				                  msg);
			} else {
				msg = std::format("{}{}", g_log_tag, msg);
			}
		}

		inline void output_log(const log_level &lev, std::string msg, std::source_location const &loc) {
			if (lev >= g_max_level) {
				init_log_msg(lev, msg, loc);
				std::println("{}", msg);
			}
		}

		inline void output_log_with_color(const log_level &lev, std::string msg, std::source_location const &loc) {
			if (lev >= g_max_level) {
				init_log_msg(lev, msg, loc);
				std::println("{}", _MINILOG_IF_HAS_ANSI_COLORS(k_level_ansi_colors[static_cast<std::uint8_t>(lev)] +)
				                   msg _MINILOG_IF_HAS_ANSI_COLORS(+ k_reset_ansi_color));
			}
		}

		inline void output_log_with_tag_color(const log_level &lev, std::string msg, std::source_location const &loc) {
			if (lev >= g_max_level) {
				std::string tag = _MINILOG_IF_HAS_ANSI_COLORS(k_level_ansi_colors[static_cast<std::uint8_t>(lev)] +)
				                  g_log_tag _MINILOG_IF_HAS_ANSI_COLORS(+ k_reset_ansi_color);

				if (lev <= log_level::debug) {
					std::println("{}{}:{}:{}, {}", tag, std::move(handleFuncName(loc)), handleFilePath(loc), loc.line(),
					             msg);
				} else {
					std::println("{}{}", tag, msg);
				}
			}
		}
	}

	inline void set_log_tag(std::string tag) {
		if (!tag.empty()) {
			details::g_log_tag = std::format("{}: ", tag);
		}
	}

	inline void set_log_level(log_level lev) {
		details::g_max_level = lev;
	}

	template<typename... Args>
	void generic_log(const log_level &lev, details::with_source_location<std::format_string<Args...> > fmt,
	                 Args &&... args) {
		auto const &loc = fmt.location();
		auto msg = std::vformat(fmt.format().get(), std::make_format_args(args...));
		details::output_log(lev, std::move(msg), loc);
	}

	template<typename... Args>
	void generic_log_with_color(const log_level &lev,
	                            details::with_source_location<std::format_string<Args...> > fmt,
	                            Args &&... args) {
		auto const &loc = fmt.location();
		auto msg = std::vformat(fmt.format().get(), std::make_format_args(args...));
#if defined(LOG_ENABLE_COLOR)
		details::output_log_with_color(lev, std::move(msg), loc);
#else
		details::output_log(lev, std::move(msg), loc);
#endif
	}

	template<typename... Args>
	void generic_log_with_tag_color(const log_level &lev,
	                                details::with_source_location<std::format_string<Args...> > fmt,
	                                Args &&... args) {
		auto const &loc = fmt.location();
		auto msg = std::vformat(fmt.format().get(), std::make_format_args(args...));
#if defined(LOG_ENABLE_COLOR)
		details::output_log_with_tag_color(lev, std::move(msg), loc);
#else
		details::output_log(lev, std::move(msg), loc);
#endif
	}

#define _FUNCTION(name) \
	template <typename... Args> \
	void log_##name(details::with_source_location<std::format_string<Args...>> fmt, Args &&...args) { \
	return generic_log(log_level::name, std::move(fmt), std::forward<Args>(args)...); \
	}
	MINILOG_FOREACH_LOG_LEVEL(_FUNCTION)
#undef _FUNCTION

#define _FUNCTION(name) \
	template <typename... Args> \
	void log_##name##_color(details::with_source_location<std::format_string<Args...>> fmt, Args &&...args) { \
	return generic_log_with_color(log_level::name, std::move(fmt), std::forward<Args>(args)...); \
	}
	MINILOG_FOREACH_LOG_LEVEL(_FUNCTION)
#undef _FUNCTION

#define _FUNCTION(name) \
	template <typename... Args> \
	void log_##name##_tag_color(details::with_source_location<std::format_string<Args...>> fmt, Args &&...args) { \
	return generic_log_with_tag_color(log_level::name, std::move(fmt), std::forward<Args>(args)...); \
	}
	MINILOG_FOREACH_LOG_LEVEL(_FUNCTION)
#undef _FUNCTION

#define MINILOG_P(x) ::minilog::log_debug(#x "={}", x)
}
