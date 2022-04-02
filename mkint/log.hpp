#pragma once

#include <cstddef>
#include <ostream>
#include <string_view>
#include <type_traits>

namespace mkint {

namespace detail {
    class log_wrapper {
    public:
        template <typename... Args>
        log_wrapper(std::ostream& stream, Args&&... args)
            : m_stream(stream)
        {
            // fold
            (void)std::initializer_list<int> {
                (m_stream << std::forward<Args>(args), 0)...
            };
        }

        log_wrapper(log_wrapper&& wrapper);
        log_wrapper(log_wrapper&) = delete;

        log_wrapper&& operator<<(std::string_view v);

        template <typename T, std::enable_if_t<std::is_convertible<T, std::string_view>::value, bool> = true>
        log_wrapper&& operator<<(const T& v)
        {
            return operator<<(std::string_view(v));
        }

        template <typename T, std::enable_if_t<!std::is_convertible<T, std::string_view>::value, bool> = true>
        log_wrapper&& operator<<(const T& v)
        {
            m_stream << v;
            m_last_was_newline = false;
            return std::move(*this);
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
detail::log_wrapper check(bool cond, bool abort, std::string_view prompt, std::string_view file, size_t line);

} // namespace mkint

#define MKINT_LOG() mkint::log()
#define MKINT_CHECK_2(cond, abort) \
    mkint::check(cond, abort, #cond, __FILE__, __LINE__)

#define MKINT_CHECK_1(cond) MKINT_CHECK_2(cond, true);

#define GET_3RD_ARG(arg1, arg2, arg3, ...) arg3
#define MKINT_CHECK_MACRO_CHOOSER(...) \
    GET_3RD_ARG(__VA_ARGS__, MKINT_CHECK_2, MKINT_CHECK_1, )
#define MKINT_CHECK(...) MKINT_CHECK_MACRO_CHOOSER(__VA_ARGS__)(__VA_ARGS__)

#define MKINT_CHECK_RELAX(cond) MKINT_CHECK_2(cond, false)
#define MKINT_CHECK_ABORT(cond) MKINT_CHECK_2(cond, true)