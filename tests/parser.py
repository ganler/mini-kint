from pyparsing import (
    delimitedList,
    Empty,
    Forward,
    Keyword,
    MatchFirst,
    Optional,
    Regex,
    restOfLine,
    ZeroOrMore,
)

def _prepare_parser():
    number = Regex(r'-?\d+')
    local = Regex(r'%[A-Za-z0-9._]+')
    glob = Regex(r'@[A-Za-z0-9._]+')
    meta = Regex(r'![A-Za-z0-9._]+')

    keywords = lambda keywords: MatchFirst(Keyword(word) for word in keywords.split())
    seplist = lambda entry: delimitedList(entry) | Empty()

    label = local + ':'

    unused_def = (keywords('target declare attributes') | '!') + restOfLine

    type_ = Forward()
    void = Keyword('void')
    scalar_type = keywords('i1 i8 i16 i32 i64') | void
    types_list = seplist(type_)
    struct_type = '{' + types_list - '}'
    array_type = '[' - number - 'x' - type_ - ']'
    type_ << (scalar_type | local | struct_type | array_type)

    type_def = local + '=' + Keyword('type') - struct_type

    value = Forward()
    typed_value = type_ + value
    value_list = seplist(typed_value)
    compound_value = '{' + value_list - '}'
    array_value = '[' + value_list - ']'
    kw_value = keywords('zeroinitializer null true false')
    value << (number | kw_value | compound_value | array_value)

    linkage = Optional(keywords('private external internal common'), 'external')
    align = Optional(',' + Keyword('align') - number)
    metas = seplist(meta + meta)
    global_tag = keywords('global constant')
    initializer = Optional(value, default='undef')
    global_def = glob - '=' - linkage - global_tag - type_ - initializer - align - metas

    definition = unused_def | type_def | global_def
    llvm = ZeroOrMore(definition)

    comment = ';' + restOfLine
    llvm.ignore(comment)

    return llvm

PARSER = _prepare_parser()