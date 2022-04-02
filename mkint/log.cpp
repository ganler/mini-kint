#include "log.hpp"
#include "rang.hpp"

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <ostream>
#include <string_view>

constexpr const char* LOG_ENV_VAR = "MKINT_LOG";

constexpr const char* LOG_PROMPT = "[MKint::LOG]";
constexpr auto LOG_STYLE_FG = rang::fg::green;
constexpr auto LOG_STYLE_BG = rang::bg::gray;

constexpr const char* CHECK_PROMPT = "[MKint::CHECK]";
constexpr auto CHECK_STYLE_FG = rang::fg::red;
constexpr auto CHECK_STYLE_BG = rang::bg::gray;

class nullstream : public std::ostream {
public:
    nullstream()
        : std::ostream(nullptr)
    {
    }
    nullstream(const nullstream&)
        : std::ostream(nullptr)
    {
    }
}; // class nullstream

template <typename T>
const nullstream& operator<<(nullstream&& os, const T& value)
{
    return os;
}

static nullstream s_null_stream;
static std::ostream& s_log_stream = []() -> std::ostream& {
    if (std::getenv(LOG_ENV_VAR)) {
        assert(std::strlen(LOG_ENV_VAR) > 0);
        static std::ofstream log_file(std::getenv(LOG_ENV_VAR));
        return log_file;
    } else if (std::getenv("MKINT_STDERR")) {
        return std::cerr;
    } else if (std::getenv("MKINT_QUIET")) {
        return s_null_stream;
    } else {
        return std::cout;
    }
}();

mkint::detail::log_wrapper::log_wrapper(mkint::detail::log_wrapper&& wrapper)
    : m_stream(wrapper.m_stream)
    , m_last_was_newline(wrapper.m_last_was_newline)
    , m_abort_at_deconstruct(wrapper.m_abort_at_deconstruct)
{
    wrapper.m_last_was_newline = false;
    wrapper.m_abort_at_deconstruct = false;
    wrapper.m_stop = true;
}

mkint::detail::log_wrapper&&
mkint::detail::log_wrapper::operator<<(std::string_view v)
{
    if (m_stop) {
        return std::move(*this);
    }

    m_stream << v;
    if (!v.empty())
        m_last_was_newline = (v.back() == '\n');
    return std::move(*this);
}

mkint::detail::log_wrapper&& mkint::detail::log_wrapper::abort_at_deconstruct()
{
    m_abort_at_deconstruct = true;
    return std::move(*this);
}

mkint::detail::log_wrapper::~log_wrapper()
{
    if (m_stop)
        return;

    if (!m_last_was_newline) {
        m_stream << std::endl;
    }

    if (m_abort_at_deconstruct) {
        std::abort();
    }
}

mkint::detail::log_wrapper mkint::log()
{
    return mkint::detail::log_wrapper(s_log_stream, LOG_STYLE_FG, LOG_STYLE_BG, LOG_PROMPT, rang::style::reset, '\t');
}

mkint::detail::log_wrapper mkint::check(bool cond, bool abort, std::string_view prompt, std::string_view file, size_t line)
{
    if (!cond) {
        auto wrapper = mkint::detail::log_wrapper(
            s_log_stream,
            CHECK_STYLE_FG, CHECK_STYLE_BG, CHECK_PROMPT, rang::style::reset, ' ',
            rang::fg::yellow, prompt, " at ", file, ':', line, '\t', rang::style::reset);

        if (abort)
            return wrapper.abort_at_deconstruct();

        else
            return wrapper;
        ;
    } else
        return mkint::detail::log_wrapper(s_null_stream);
}
