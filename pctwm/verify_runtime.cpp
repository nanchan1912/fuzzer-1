#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <cctype>
#include <iostream>

// Simple lock-free variable storage (no pthread mutex to avoid creating happens-before synchronization edges)
struct VarEntry {
    char name[64];
    bool value;
    bool valid;
};

static VarEntry g_var_table[64] = {};

extern "C" {

void __VERIFY_STORE_VAR(const char *name, bool value) {
    if (!name) return;
    for (int i = 0; i < 64; i++) {
        if (!g_var_table[i].valid) {
            strncpy(g_var_table[i].name, name, 63);
            g_var_table[i].name[63] = '\0';
            g_var_table[i].value = value;
            g_var_table[i].valid = true;
            return;
        } else if (strcmp(g_var_table[i].name, name) == 0) {
            g_var_table[i].value = value;
            return;
        }
    }
}

}

// Simple recursive descent parser for boolean expressions
namespace {
    struct ExprParser {
        const std::string s;
        size_t pos;

        ExprParser(const char *expr) : s(expr ? expr : ""), pos(0) {}

        void skip_ws() {
            while (pos < s.size() && std::isspace((unsigned char)s[pos])) {
                pos++;
            }
        }

        bool match(const std::string &token) {
            skip_ws();
            if (s.substr(pos, token.size()) == token) {
                pos += token.size();
                return true;
            }
            return false;
        }

        bool peek(char c) {
            skip_ws();
            return pos < s.size() && s[pos] == c;
        }

        bool parse_expr() {
            return parse_or();
        }

        bool parse_or() {
            bool val = parse_and();
            while (true) {
                if (match("||") || match("|")) {
                    bool right = parse_and();
                    val = val || right;
                } else {
                    break;
                }
            }
            return val;
        }

        bool parse_and() {
            bool val = parse_xor();
            while (true) {
                if (match("&&") || match("&")) {
                    bool right = parse_xor();
                    val = val && right;
                } else {
                    break;
                }
            }
            return val;
        }

        bool parse_xor() {
            bool val = parse_equality();
            while (match("^")) {
                bool right = parse_equality();
                val = (val != right);
            }
            return val;
        }

        bool parse_equality() {
            bool val = parse_unary();
            while (true) {
                if (match("==")) {
                    bool right = parse_unary();
                    val = (val == right);
                } else if (match("!=")) {
                    bool right = parse_unary();
                    val = (val != right);
                } else {
                    break;
                }
            }
            return val;
        }

        bool parse_unary() {
            skip_ws();
            if (match("!") || match("~")) {
                return !parse_unary();
            }
            return parse_primary();
        }

        bool parse_primary() {
            skip_ws();
            if (match("(")) {
                bool val = parse_expr();
                match(")");
                return val;
            }

            // Parse identifier or literal
            size_t start = pos;
            while (pos < s.size() && (std::isalnum((unsigned char)s[pos]) || s[pos] == '_')) {
                pos++;
            }
            std::string ident = s.substr(start, pos - start);
            if (ident == "true" || ident == "1") return true;
            if (ident == "false" || ident == "0") return false;

            for (int i = 0; i < 64; i++) {
                if (g_var_table[i].valid && ident == g_var_table[i].name) {
                    return g_var_table[i].value;
                }
            }
            // Default to false if uninitialized
            return false;
        }
    };
}

extern "C" {
__attribute__((weak)) void model_assert(bool expr, const char *file, int line);

bool __VERIFY_ASSERT(const char *expr) {
    if (!expr) return true;
    ExprParser parser(expr);
    bool result = parser.parse_expr();
    if (!result) {
        std::cerr << "\n=================================================================\n";
        std::cerr << "[PCTWM ASSERTION FAILED] Assertion failed: \"" << expr << "\"\n";
        std::cerr << "Recorded Variable State:\n";
        for (int i = 0; i < 64; i++) {
            if (g_var_table[i].valid) {
                std::cerr << "  " << g_var_table[i].name << " = " << (g_var_table[i].value ? "true" : "false") << "\n";
            }
        }
        std::cerr << "=================================================================\n" << std::flush;
        if (model_assert) {
            model_assert(false, "verify_runtime", 0);
        } else {
            _Exit(101);
        }
    }
    return result;
}

}

