#pragma once

#include <llvm/Support/raw_ostream.h>

#include <cstddef>
#include <iostream>
#include <ostream>
#include <string_view>
#include <type_traits>

namespace mkint {

namespace detail {

    template <typename T, typename = void> inline constexpr bool is_streamable_v = false;

    template <typename T>
    inline constexpr bool
        is_streamable_v<T, std::void_t<decltype(std::declval<std::ostream&>() << std::declval<T>())>> = true;

    class log_wrapper {
    public:
        template <typename... Args>
        log_wrapper(std::ostream& stream, Args&&... args)
            : m_stream(stream)
        {
            // fold
            (void)std::initializer_list<int> { (m_stream << std::forward<Args>(args), 0)... };
        }

        log_wrapper(log_wrapper&& wrapper);
        log_wrapper(log_wrapper&) = delete;

        log_wrapper&& operator<<(std::string_view v);

        template <typename T>
        std::enable_if_t<std::is_convertible_v<T, std::string_view>, log_wrapper&&> operator<<(const T& v)
        {
            return operator<<(std::string_view(v));
        }

        template <typename T>
        std::enable_if_t<!std::is_convertible_v<T, std::string_view> && is_streamable_v<T>, log_wrapper&&> operator<<(
            const T& v)
        {
            m_stream << v;
            m_last_was_newline = false;
            return std::move(*this);
        }

        template <typename T>
        std::enable_if_t<!std::is_convertible<T, std::string_view>::value && !is_streamable_v<T>, log_wrapper&&>
        operator<<(const T& v)
        {
            std::string str;
            llvm::raw_string_ostream(str) << v;
            return operator<<(str);
        }

        log_wrapper&& abort_at_deconstruct();

        ~log_wrapper();

    private:
        std::ostream& m_stream;
        bool m_last_was_newline = false;
        bool m_abort_at_deconstruct = false;
        bool m_stop = false;
    }; // class log_wrapper
}

detail::log_wrapper log();
detail::log_wrapper debug();
detail::log_wrapper warn();
detail::log_wrapper check(bool cond, bool abort, std::string_view prompt, std::string_view file, size_t line);

} // namespace mkint

#define MKINT_LOG() mkint::log()
#define MKINT_DEBUG() mkint::debug()
#define MKINT_WARN() mkint::warn()

#define MKINT_CHECK_1(cond) mkint::check(cond, true, #cond, __FILE__, __LINE__)
#define MKINT_CHECK_2(cond, abort) mkint::check(cond, abort, #cond, __FILE__, __LINE__)

#define MKINT_CHECK_X(x, cond, abort, FUNC, ...) FUNC
#define MKINT_CHECK(...) MKINT_CHECK_X(, ##__VA_ARGS__, MKINT_CHECK_2(__VA_ARGS__), MKINT_CHECK_1(__VA_ARGS__))

#define MKINT_CHECK_RELAX(cond) MKINT_CHECK_2(cond, false)
#define MKINT_CHECK_ABORT(cond) MKINT_CHECK_2(cond, true)