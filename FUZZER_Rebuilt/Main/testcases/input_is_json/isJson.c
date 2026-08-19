#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

/* Simple, incomplete JSON validator just for demonstration/testing purposes.
   A real implementation would use a proper library like cJSON or Jansson.
   However, for a simple test case to verify if input *looks* like JSON,
   we can just check basic structure or rely on an external library if available.
   
   Given the constraint of a single file test case without external dependencies mentioned,
   I'll implement a very basic check: does it start with { or [ and end with } or ]?
   Or better, let's assume valid JSON for the purpose of this test is just parsing 
   the structure successfully.
   
   Since writing a full JSON parser in a single file is complex, and the prompt implies
   we just want to detect if the mutator is generating JSON, let's look for curly braces.
*/

int is_json_heuristic(const char *buf, size_t len) {
    size_t i = 0;
    while (i < len && isspace(buf[i])) i++;
    if (i == len) return 0; // Empty or whitespace only

    if (buf[i] != '{' && buf[i] != '[') return 0; // Must start with object or array

    // Find end
    size_t j = len - 1;
    while (j > i && isspace(buf[j])) j--;
    
    if (buf[i] == '{' && buf[j] == '}') return 1;
    if (buf[i] == '[' && buf[j] == ']') return 1;

    return 0;
}

// A slightly more robust check using a tiny parser state machine would be better
// but for a "fail if valid json" test, heuristic might be enough if the mutator
// generates standard JSON.
// Let's implement a minimal recursive descent syntax checker for strict validation?
// That might be overkill. Let's stick to the heuristic or basic nesting check.

int check_balanced(const char *buf, size_t len) {
    int depth = 0;
    int in_string = 0;
    int escape = 0;
    
    for (size_t i = 0; i < len; i++) {
        char c = buf[i];
        if (in_string) {
            if (escape) {
                escape = 0;
            } else if (c == '\\') {
                escape = 1;
            } else if (c == '"') {
                in_string = 0;
            }
        } else {
            if (c == '"') {
                in_string = 1;
            } else if (c == '{' || c == '[') {
                depth++;
            } else if (c == '}' || c == ']') {
                depth--;
                if (depth < 0) return 0;
            }
        }
    }
    return depth == 0;
}

int main(int argc, char **argv) {
    char *input_file = getenv("FUZZ_INPUT");
    FILE *f = stdin;

    if (input_file) {
        f = fopen(input_file, "rb");
        if (!f) return 0; // Don't crash on file error
    } else if (argc > 1) {
        f = fopen(argv[1], "rb");
        if (!f) return 0;
    }

    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (length < 2) return 0; // Too short for JSON

    char *buffer = malloc(length + 1);
    if (!buffer) return 0;
    
    if (fread(buffer, 1, length, f) != length) {
        free(buffer);
        if (f != stdin) fclose(f);
        return 0;
    }
    buffer[length] = '\0';
    if (f != stdin) fclose(f);

    FILE *log = fopen("input_log.txt", "a");
    if (log) {
        fprintf(log, "--- Input ---\n");
        fwrite(buffer, 1, length, log);
        fprintf(log, "\n");
        fclose(log);
    }

    // Basic validation
    if (!is_json_heuristic(buffer, length) || !check_balanced(buffer, length)) {
        // IT IS NOT JSON! CRASH!
        free(buffer);
        abort(); 
    }

    free(buffer);
    return 0;
}
