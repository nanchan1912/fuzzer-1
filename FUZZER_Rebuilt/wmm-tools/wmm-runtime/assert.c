#include "assert.h"

#include <ctype.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	char *name;
	bool value;
	bool in_use;
} verify_var_slot_t;

typedef struct {
	verify_var_slot_t *slots;
	size_t capacity;
	size_t count;
	pthread_rwlock_t lock;
} verify_var_table_t;

static verify_var_table_t g_verify_vars = {
	.slots = NULL,
	.capacity = 0,
	.count = 0,
	.lock = PTHREAD_RWLOCK_INITIALIZER,
};

static uint64_t verify_hash_name(const char *s) {
	uint64_t hash = 1469598103934665603ULL;
	while (*s) {
		hash ^= (unsigned char)*s;
		hash *= 1099511628211ULL;
		++s;
	}
	return hash;
}

static bool verify_table_init_locked(verify_var_table_t *table) {
	if (table->slots)
		return true;

	const size_t initial_capacity = 64;
	table->slots = (verify_var_slot_t *)calloc(initial_capacity, sizeof(*table->slots));
	if (!table->slots)
		return false;

	table->capacity = initial_capacity;
	table->count = 0;
	return true;
}

static bool verify_table_insert_owned_locked(verify_var_table_t *table,
											 char *owned_name,
											 bool value) {
	if (!verify_table_init_locked(table))
		return false;

	const uint64_t hash = verify_hash_name(owned_name);
	size_t index = (size_t)(hash & (table->capacity - 1));

	while (table->slots[index].in_use) {
		if (strcmp(table->slots[index].name, owned_name) == 0) {
			free(owned_name);
			table->slots[index].value = value;
			return true;
		}
		index = (index + 1) & (table->capacity - 1);
	}

	table->slots[index].name = owned_name;
	table->slots[index].value = value;
	table->slots[index].in_use = true;
	table->count += 1;
	return true;
}

static bool verify_table_rehash_locked(verify_var_table_t *table, size_t new_capacity) {
	verify_var_slot_t *new_slots = (verify_var_slot_t *)calloc(new_capacity, sizeof(*new_slots));
	if (!new_slots)
		return false;

	verify_var_slot_t *old_slots = table->slots;
	const size_t old_capacity = table->capacity;

	table->slots = new_slots;
	table->capacity = new_capacity;
	table->count = 0;

	for (size_t i = 0; i < old_capacity; ++i) {
		if (!old_slots[i].in_use)
			continue;
		if (!verify_table_insert_owned_locked(table, old_slots[i].name, old_slots[i].value)) {
			for (size_t j = 0; j < new_capacity; ++j) {
				if (table->slots[j].in_use)
					free(table->slots[j].name);
			}
			free(table->slots);
			table->slots = old_slots;
			table->capacity = old_capacity;
			table->count = 0;
			for (size_t j = 0; j < old_capacity; ++j) {
				if (old_slots[j].in_use)
					table->count += 1;
			}
			return false;
		}
	}

	free(old_slots);
	return true;
}

static bool verify_table_set_locked(verify_var_table_t *table, const char *name, bool value) {
	if (!name || !*name)
		return false;

	if (!verify_table_init_locked(table))
		return false;

	if ((table->count + 1) * 100 >= table->capacity * 70) {
		if (!verify_table_rehash_locked(table, table->capacity * 2))
			return false;
	}

	char *owned_name = strdup(name);
	if (!owned_name)
		return false;

	return verify_table_insert_owned_locked(table, owned_name, value);
}

static bool verify_table_get_locked(const verify_var_table_t *table,
									const char *name,
									bool *out_value) {
	if (!table->slots || !name || !*name)
		return false;

	const uint64_t hash = verify_hash_name(name);
	size_t index = (size_t)(hash & (table->capacity - 1));
	size_t probes = 0;

	while (probes < table->capacity) {
		if (!table->slots[index].in_use)
			return false;
		if (strcmp(table->slots[index].name, name) == 0) {
			*out_value = table->slots[index].value;
			return true;
		}
		index = (index + 1) & (table->capacity - 1);
		probes += 1;
	}

	return false;
}

typedef struct {
	const char *expr;
	size_t pos;
	const char *error;
	bool unknown_var;
} verify_parser_t;

static void verify_skip_ws(verify_parser_t *parser) {
	while (parser->expr[parser->pos] != '\0' &&
		   isspace((unsigned char)parser->expr[parser->pos])) {
		parser->pos += 1;
	}
}

static bool verify_parse_or(verify_parser_t *parser, bool *out);

static bool verify_lookup_name(const char *name, bool *out) {
	bool found = false;
	pthread_rwlock_rdlock(&g_verify_vars.lock);
	found = verify_table_get_locked(&g_verify_vars, name, out);
	pthread_rwlock_unlock(&g_verify_vars.lock);
	return found;
}

static bool verify_parse_ident(verify_parser_t *parser,
							   char *buffer,
							   size_t buffer_size) {
	const char c = parser->expr[parser->pos];
	if (!(isalpha((unsigned char)c) || c == '_'))
		return false;

	size_t written = 0;
	while (parser->expr[parser->pos] != '\0') {
		const char ch = parser->expr[parser->pos];
		if (!(isalnum((unsigned char)ch) || ch == '_'))
			break;
		if (written + 1 >= buffer_size) {
			parser->error = "identifier too long";
			return false;
		}
		buffer[written++] = ch;
		parser->pos += 1;
	}
	buffer[written] = '\0';
	return true;
}

static bool verify_parse_primary(verify_parser_t *parser, bool *out) {
	verify_skip_ws(parser);
	const char c = parser->expr[parser->pos];

	if (c == '(') {
		parser->pos += 1;
		if (!verify_parse_or(parser, out))
			return false;
		verify_skip_ws(parser);
		if (parser->expr[parser->pos] != ')') {
			parser->error = "missing ')'";
			return false;
		}
		parser->pos += 1;
		return true;
	}

	if (c == '0') {
		parser->pos += 1;
		*out = false;
		return true;
	}
	if (c == '1') {
		parser->pos += 1;
		*out = true;
		return true;
	}

	char name[256];
	if (!verify_parse_ident(parser, name, sizeof(name))) {
		if (!parser->error)
			parser->error = "expected identifier, '0', '1', or '('";
		return false;
	}

	if (strcmp(name, "true") == 0) {
		*out = true;
		return true;
	}
	if (strcmp(name, "false") == 0) {
		*out = false;
		return true;
	}

	if (!verify_lookup_name(name, out)) {
		parser->unknown_var = true;
		parser->error = "unknown variable";
		return false;
	}
	return true;
}

static bool verify_parse_unary(verify_parser_t *parser, bool *out) {
	verify_skip_ws(parser);
	if (parser->expr[parser->pos] == '!') {
		parser->pos += 1;
		bool val = false;
		if (!verify_parse_unary(parser, &val))
			return false;
		*out = !val;
		return true;
	}
	return verify_parse_primary(parser, out);
}

static bool verify_parse_and(verify_parser_t *parser, bool *out) {
	bool lhs = false;
	if (!verify_parse_unary(parser, &lhs))
		return false;

	while (1) {
		verify_skip_ws(parser);
		if (parser->expr[parser->pos] != '&')
			break;
		parser->pos += 1;

		bool rhs = false;
		if (!verify_parse_unary(parser, &rhs))
			return false;
		lhs = lhs && rhs;
	}

	*out = lhs;
	return true;
}

static bool verify_parse_or(verify_parser_t *parser, bool *out) {
	bool lhs = false;
	if (!verify_parse_and(parser, &lhs))
		return false;

	while (1) {
		verify_skip_ws(parser);
		if (parser->expr[parser->pos] != '|')
			break;
		parser->pos += 1;

		bool rhs = false;
		if (!verify_parse_and(parser, &rhs))
			return false;
		lhs = lhs || rhs;
	}

	*out = lhs;
	return true;
}

static bool verify_eval_expr(const char *expr, bool *out, const char **error) {
	if (!expr || !*expr) {
		if (error)
			*error = "empty expression";
		return false;
	}

	verify_parser_t parser = {
		.expr = expr,
		.pos = 0,
		.error = NULL,
		.unknown_var = false,
	};

	if (!verify_parse_or(&parser, out)) {
		if (error)
			*error = parser.error ? parser.error : "parse failure";
		return false;
	}

	verify_skip_ws(&parser);
	if (parser.expr[parser.pos] != '\0') {
		if (error)
			*error = "unexpected trailing token";
		return false;
	}

	return true;
}

void __VERIFY_STORE_VAR(const char *name, bool value) {
	if (!name || !*name) {
		fprintf(stderr, "[VERIFY] __VERIFY_STORE_VAR: invalid variable name\n");
		abort();
	}

	pthread_rwlock_wrlock(&g_verify_vars.lock);
	const bool ok = verify_table_set_locked(&g_verify_vars, name, value);
	pthread_rwlock_unlock(&g_verify_vars.lock);

	if (!ok) {
		fprintf(stderr,
				"[VERIFY] __VERIFY_STORE_VAR: failed to store variable '%s'\n",
				name);
		abort();
	}
}

bool __VERIFY_ASSERT(const char *expr) {
	bool result = false;
	const char *error = NULL;

	if (!verify_eval_expr(expr, &result, &error)) {
		fprintf(stderr,
				"[VERIFY] __VERIFY_ASSERT parse/eval failure: expr=\"%s\" error=%s\n",
				expr ? expr : "<null>",
				error ? error : "unknown");
		abort();
	}

	if (!result) {
		fprintf(stderr,
				"[VERIFY] assertion failed: expr=\"%s\"\n",
				expr ? expr : "<null>");
		abort();
	}

	return true;
}
