package io.github.refurbcheck;

import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

/** Bounded, read-only report input. Parsing does not authorize any remediation action. */
public final class ReportJson {
    public static final int MAX_BYTES = 8 * 1024 * 1024;
    public static final int MAX_DEPTH = 64;
    private static final int MAX_VALUES = 200000;
    private ReportJson() { }

    public static JSONObject parse(byte[] bytes) throws IOException {
        if (bytes == null || bytes.length == 0 || bytes.length > MAX_BYTES)
            throw new IOException("보고서 파일은 비어 있지 않은 8 MiB 이하 JSON이어야 합니다.");
        final String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException exception) { throw new IOException("보고서가 올바른 UTF-8 형식이 아닙니다.", exception); }
        // This nonrecursive pass runs before both the syntax validator and Android's recursive parser.
        guardDepth(text);
        new Syntax(text).validate();
        try {
            JSONTokener parser = new JSONTokener(text);
            Object value = parser.nextValue();
            if (!(value instanceof JSONObject) || parser.nextClean() != 0)
                throw new IOException("보고서는 JSON 객체 한 개여야 하며 뒤에 다른 데이터가 없어야 합니다.");
            return (JSONObject) value;
        } catch (Exception exception) { throw new IOException("보고서 JSON을 해석할 수 없습니다.", exception); }
    }

    private static void guardDepth(String text) throws IOException {
        char[] stack = new char[MAX_DEPTH];
        int depth = 0; boolean quoted = false, escaped = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (quoted) {
                if (escaped) escaped = false;
                else if (c == '\\') escaped = true;
                else if (c == '"') quoted = false;
            } else if (c == '"') quoted = true;
            else if (c == '{' || c == '[') {
                if (depth == MAX_DEPTH) throw new IOException("보고서 JSON 중첩이 64단계를 초과합니다.");
                stack[depth++] = c;
            } else if (c == '}' || c == ']') {
                if (depth == 0 || stack[--depth] != (c == '}' ? '{' : '['))
                    throw new IOException("보고서 JSON 괄호가 잘못되었거나 잘렸습니다.");
            }
        }
        if (quoted || depth != 0) throw new IOException("보고서 JSON 문자열 또는 구조가 잘렸습니다.");
    }

    /** Validates standard JSON without constructing the report or accepting org.json's extensions. */
    private static final class Syntax {
        final String input;
        int position, values;
        Syntax(String input) { this.input = input; }
        void validate() throws IOException {
            whitespace();
            if (peek() != '{') throw bad("최상위 값은 객체여야 합니다");
            value(); whitespace();
            if (position != input.length()) throw bad("JSON 뒤에 다른 데이터가 있습니다");
        }
        void value() throws IOException {
            if (++values > MAX_VALUES) throw bad("JSON 항목 수가 너무 많습니다");
            whitespace(); char c = peek();
            if (c == '{') object();
            else if (c == '[') array();
            else if (c == '"') string();
            else if (c == 't') literal("true");
            else if (c == 'f') literal("false");
            else if (c == 'n') literal("null");
            else if (c == '-' || c >= '0' && c <= '9') number();
            else throw bad("잘못된 JSON 값입니다");
        }
        void object() throws IOException {
            position++; whitespace();
            Set<String> keys = new HashSet<>();
            if (take('}')) return;
            do {
                whitespace();
                if (peek() != '"') throw bad("객체 이름은 큰따옴표 문자열이어야 합니다");
                String key = string();
                if (!keys.add(key)) throw bad("같은 객체에 중복된 이름이 있습니다");
                whitespace(); require(':'); value(); whitespace();
                if (take('}')) return;
                require(',');
            } while (true);
        }
        void array() throws IOException {
            position++; whitespace();
            if (take(']')) return;
            do {
                value(); whitespace();
                if (take(']')) return;
                require(',');
            } while (true);
        }
        String string() throws IOException {
            require('"'); StringBuilder decoded = new StringBuilder();
            boolean pendingHighSurrogate = false;
            while (position < input.length()) {
                char c = input.charAt(position++);
                if (c == '"') {
                    if (pendingHighSurrogate) throw bad("잘못된 Unicode 문자열입니다");
                    return decoded.toString();
                }
                if (c < 0x20) throw bad("문자열에 이스케이프되지 않은 제어 문자가 있습니다");
                if (c == '\\') {
                    if (position >= input.length()) throw bad("문자열 이스케이프가 잘렸습니다");
                    c = input.charAt(position++);
                    switch (c) {
                        case '"': case '\\': case '/': break;
                        case 'b': c = '\b'; break;
                        case 'f': c = '\f'; break;
                        case 'n': c = '\n'; break;
                        case 'r': c = '\r'; break;
                        case 't': c = '\t'; break;
                        case 'u':
                            if (input.length() - position < 4) throw bad("Unicode 이스케이프가 잘렸습니다");
                            int code = 0;
                            for (int i = 0; i < 4; i++) {
                                char digit = input.charAt(position++);
                                int hex = digit >= '0' && digit <= '9' ? digit - '0'
                                        : digit >= 'a' && digit <= 'f' ? digit - 'a' + 10
                                        : digit >= 'A' && digit <= 'F' ? digit - 'A' + 10 : -1;
                                if (hex < 0) throw bad("잘못된 Unicode 이스케이프입니다");
                                code = code * 16 + hex;
                            }
                            c = (char) code; break;
                        default: throw bad("잘못된 문자열 이스케이프입니다");
                    }
                }
                if (pendingHighSurrogate) {
                    if (!Character.isLowSurrogate(c)) throw bad("잘못된 Unicode surrogate 쌍입니다");
                    pendingHighSurrogate = false;
                } else if (Character.isLowSurrogate(c)) throw bad("짝이 없는 Unicode surrogate입니다");
                else if (Character.isHighSurrogate(c)) pendingHighSurrogate = true;
                decoded.append(c);
            }
            throw bad("문자열이 잘렸습니다");
        }
        void number() throws IOException {
            int start = position;
            take('-');
            if (take('0')) {
                if (digit(peek())) throw bad("JSON 숫자의 앞에 불필요한 0이 있습니다");
            } else {
                if (peek() < '1' || peek() > '9') throw bad("잘못된 JSON 숫자입니다");
                while (digit(peek())) position++;
            }
            if (take('.')) { requireDigit(); while (digit(peek())) position++; }
            if (take('e') || take('E')) {
                if (!take('+')) take('-');
                requireDigit(); while (digit(peek())) position++;
            }
            if (position - start > 128) throw bad("JSON 숫자가 너무 깁니다");
        }
        void requireDigit() throws IOException { if (!digit(peek())) throw bad("JSON 숫자가 잘렸습니다"); }
        boolean digit(char c) { return c >= '0' && c <= '9'; }
        void literal(String word) throws IOException {
            if (!input.startsWith(word, position)) throw bad("잘못된 JSON 리터럴입니다");
            position += word.length();
        }
        void whitespace() {
            while (position < input.length()) {
                char c = input.charAt(position);
                if (c != ' ' && c != '\t' && c != '\n' && c != '\r') return;
                position++;
            }
        }
        char peek() { return position < input.length() ? input.charAt(position) : 0; }
        boolean take(char c) { if (position < input.length() && input.charAt(position) == c) { position++; return true; } return false; }
        void require(char c) throws IOException { if (!take(c)) throw bad("예상한 JSON 구분자가 없습니다"); }
        IOException bad(String message) { return new IOException(message + " (문자 위치 " + position + ")"); }
    }
}
