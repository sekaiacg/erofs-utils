#pragma once

#include <memory>

namespace skkk::erofs {
	template<typename T>
	class Buffer {
		uint64_t size_ = 0;
		std::unique_ptr<T[]> data_;

		void allocate(uint64_t size) {
			this->size_ = size;
			this->data_ = std::make_unique<T[]>(sizeof(T) * size);
		}

		void setValue(T value) {
			switch (sizeof(T)) {
				case 1:
					memset(data_.get(), value, size_);
					break;
				default:
					for (uint64_t i = 0; i < size_; i++) {
						data_[i] = value;
					}
			}
		}

		public:
			Buffer() = default;

			explicit Buffer(uint64_t size) {
				allocate(size);
			}

			explicit Buffer(T value, uint64_t size) {
				allocate(size);
				setValue(value);
			}

			Buffer(const Buffer &other) = delete;

			Buffer &operator=(const Buffer &other) = delete;

			Buffer(Buffer &&other)
				noexcept : size_(other.size_),
				           data_(std::move(other.data_)) {
			}

			Buffer &operator=(Buffer &&other) noexcept {
				if (this == &other)
					return *this;
				size_ = other.size_;
				data_ = std::move(other.data_);
				return *this;
			}

			void reserve(uint64_t size) {
				allocate(size);
			}

			void reserve(T value, uint64_t size) {
				allocate(size);
				setValue(value);
			}

			void resize(uint64_t size) {
				allocate(size);
			}

			void resize(T value, uint64_t size) {
				allocate(size);
				setValue(value);
			}

			T *get() {
				return data_.get();
			}
	};
}
