#pragma once

#include <concepts>
#include <format>
#include <iostream>
#include <ranges>
#include <string>
#include <sstream>
#include <type_traits>
#include <utility>

#if !defined(__cpp_lib_format_ranges)
namespace std {
	template<typename T>
	concept is_string_element =
			std::same_as<std::remove_cvref_t<T>, std::string> ||
			std::same_as<std::remove_cvref_t<T>, std::string_view> ||
			(std::is_array_v<std::remove_reference_t<T> > && std::same_as<std::remove_cvref_t<std::decay_t<T> >, char
				 *>) ||
			std::same_as<std::remove_cvref_t<T>, const char *> ||
			std::same_as<std::remove_cvref_t<T>, char *>;

	template<typename T>
	concept is_char_element = std::same_as<std::remove_cvref_t<T>, char>;

	template<typename T>
	concept is_map_like = requires(T t)
	{
		typename std::remove_cvref_t<T>::key_type;
		typename std::remove_cvref_t<T>::mapped_type;
	};

	template<typename T1, typename T2, typename CharT>
	struct formatter<std::pair<T1, T2>, CharT>;

	template<typename CharT, typename T>
	void format_element_to_stream(std::basic_ostringstream<CharT> &oss, const T &val) {
		if constexpr (is_string_element<T>) {
			oss << "\"" << val << "\"";
		} else if constexpr (is_char_element<T>) {
			oss << "'" << val << "'";
		} else {
			oss << std::format("{}", val);
		}
	}

	template<typename T1, typename T2, typename CharT>
	struct formatter<std::pair<T1, T2>, CharT> : formatter<std::string, CharT> {
		template<typename FormatContext>
		auto format(const std::pair<T1, T2> &p, FormatContext &ctx) const {
			std::basic_ostringstream<CharT> oss;
			oss << "(";
			format_element_to_stream(oss, p.first);
			oss << ", ";
			format_element_to_stream(oss, p.second);
			oss << ")";
			return formatter<std::string, CharT>::format(oss.str(), ctx);
		}
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
					format_element_to_stream(oss, it->first);
					oss << ": ";
					format_element_to_stream(oss, it->second);
					if (std::next(it) != std::ranges::end(range)) oss << ", ";
				}
				oss << "}";
			} else {
				oss << "[";
				for (auto it = std::ranges::begin(range); it != std::ranges::end(range); ++it) {
					format_element_to_stream(oss, *it);
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
