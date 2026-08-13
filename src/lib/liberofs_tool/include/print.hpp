#pragma once

#include <concepts>
#include <format>
#include <iostream>
#include <ranges>
#include <string>
#include <sstream>
#include <utility>
#include <type_traits>

#if !defined(__cpp_lib_format_ranges)
namespace std {
	template<typename T1, typename T2, typename CharT>
	struct formatter<std::pair<T1, T2>, CharT> : formatter<std::string, CharT> {
		template<typename FormatContext>
		auto format(const std::pair<T1, T2> &p, FormatContext &ctx) const {
			std::basic_ostringstream<CharT> oss;
			oss << "(" << std::format("{}", p.first) << ", " << std::format("{}", p.second) << ")";
			return formatter<std::string, CharT>::format(oss.str(), ctx);
		}
	};

	template<typename T>
	concept is_map_like = requires(T t)
	{
		typename std::remove_cvref_t<T>::key_type;
		typename std::remove_cvref_t<T>::mapped_type;
	};

	template<typename R, typename CharT>
		requires std::ranges::input_range<R> &&
		         (!std::same_as<std::remove_cvref_t<R>, std::string>) &&
		         (!std::same_as<std::remove_cvref_t<R>, std::string_view>)
	struct formatter<R, CharT> : formatter<std::string, CharT> {
		template<typename FormatContext>
		auto format(const R &range, FormatContext &ctx) const {
			std::basic_ostringstream<CharT> oss;
			if constexpr (is_map_like<R>) {
				oss << "{";
				for (auto it = std::ranges::begin(range); it != std::ranges::end(range); ++it) {
					oss << std::format("{}", it->first) << ": " << std::format("{}", it->second);
					if (std::next(it) != std::ranges::end(range)) oss << ", ";
				}
				oss << "}";
			} else {
				oss << "[";
				for (auto it = std::ranges::begin(range); it != std::ranges::end(range); ++it) {
					oss << std::format("{}", *it);
					if (std::next(it) != std::ranges::end(range)) oss << ", ";
				}
				oss << "]";
			}
			return formatter<std::string, CharT>::format(oss.str(), ctx);
		}
	};
}
#endif

#if defined(__cpp_lib_print)
#include <print>
#else
namespace std {
	template<typename... Args>
	void print(std::format_string<Args...> fmt, Args &&... args) {
		std::cout << std::format(fmt, std::forward<Args>(args)...);
	}

	template<typename... Args>
	void println(std::format_string<Args...> fmt, Args &&... args) {
		std::cout << std::format(fmt, std::forward<Args>(args)...) << '\n';
	}

	inline void println() {
		std::cout << '\n';
	}

	template<typename... Args>
	void print(std::ostream &os, std::format_string<Args...> fmt, Args &&... args) {
		os << std::format(fmt, std::forward<Args>(args)...);
	}

	template<typename... Args>
	void println(std::ostream &os, std::format_string<Args...> fmt, Args &&... args) {
		os << std::format(fmt, std::forward<Args>(args)...) << '\n';
	}
}
#endif
