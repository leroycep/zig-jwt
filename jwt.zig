const std = @import("std");
const testing = std.testing;
const ValueTree = std.json.ValueTree;
const Value = std.json.Value;
const base64url = std.base64.url_safe_no_pad;

const Algorithm = enum {
    const Self = @This();

    HS256,
    HS384,
    HS512,

    pub fn jsonStringify(value: Self, options: std.json.StringifyOptions, writer: anytype) @TypeOf(writer).Error!void {
        try std.json.stringify(std.meta.tagName(value), options, writer);
    }

    pub fn CryptoFn(comptime self: Self) type {
        return switch (self) {
            .HS256 => std.crypto.auth.hmac.sha2.HmacSha256,
            .HS384 => std.crypto.auth.hmac.sha2.HmacSha384,
            .HS512 => std.crypto.auth.hmac.sha2.HmacSha512,
        };
    }
};

const JWTType = enum {
    JWS,
    JWE,
};

pub const SignatureOptions = struct {
    key: []const u8,
    kid: ?[]const u8 = null,
};

pub fn encode(allocator: std.mem.Allocator, comptime alg: Algorithm, payload: anytype, signatureOptions: SignatureOptions) ![]const u8 {
    var payload_json = std.ArrayList(u8).init(allocator);
    defer payload_json.deinit();

    try std.json.stringify(payload, .{}, payload_json.writer());

    return try encodeMessage(allocator, alg, payload_json.items, signatureOptions);
}

pub fn encodeMessage(allocator: std.mem.Allocator, comptime alg: Algorithm, message: []const u8, signatureOptions: SignatureOptions) ![]const u8 {
    var protected_header = std.json.ObjectMap.init(allocator);
    defer protected_header.deinit();
    try protected_header.put("alg", .{ .string = std.meta.tagName(alg) });
    try protected_header.put("typ", .{ .string = "JWT" });
    if (signatureOptions.kid) |kid| {
        try protected_header.put("kid", .{ .string = kid });
    }

    var protected_header_json = std.ArrayList(u8).init(allocator);
    defer protected_header_json.deinit();

    try std.json.stringify(Value{ .object = protected_header }, .{}, protected_header_json.writer());

    const message_base64_len = base64url.Encoder.calcSize(message.len);
    const protected_header_base64_len = base64url.Encoder.calcSize(protected_header_json.items.len);

    var jwt_text = std.ArrayList(u8).init(allocator);
    defer jwt_text.deinit();
    try jwt_text.resize(message_base64_len + 1 + protected_header_base64_len);

    var protected_header_base64 = jwt_text.items[0..protected_header_base64_len];
    var message_base64 = jwt_text.items[protected_header_base64_len + 1 ..][0..message_base64_len];

    _ = base64url.Encoder.encode(protected_header_base64, protected_header_json.items);
    jwt_text.items[protected_header_base64_len] = '.';
    _ = base64url.Encoder.encode(message_base64, message);

    const signature = &generate_signature(alg, signatureOptions.key, protected_header_base64, message_base64);
    const signature_base64_len = base64url.Encoder.calcSize(signature.len);

    try jwt_text.resize(message_base64_len + 1 + protected_header_base64_len + 1 + signature_base64_len);
    var signature_base64 = jwt_text.items[message_base64_len + 1 + protected_header_base64_len + 1 ..][0..signature_base64_len];

    jwt_text.items[message_base64_len + 1 + protected_header_base64_len] = '.';
    _ = base64url.Encoder.encode(signature_base64, signature);

    return jwt_text.toOwnedSlice();
}

pub fn validate(comptime P: type, allocator: std.mem.Allocator, comptime alg: Algorithm, tokenText: []const u8, signatureOptions: SignatureOptions) !P {
    const message = try validateMessage(allocator, alg, tokenText, signatureOptions);
    defer allocator.free(message);

    // 10.  Verify that the resulting octet sequence is a UTF-8-encoded
    //      representation of a completely valid JSON object conforming to
    //      RFC 7159 [RFC7159]; let the JWT Claims Set be this JSON object.
    return std.json.parseFromSlice(P, allocator, message, .{});
}

pub fn validateFree(comptime P: type, allocator: std.mem.Allocator, value: P) void {
    std.json.parseFree(P, allocator, value);
}

pub fn validateMessage(allocator: std.mem.Allocator, comptime expectedAlg: Algorithm, tokenText: []const u8, signatureOptions: SignatureOptions) ![]const u8 {
    // 1.   Verify that the JWT contains at least one period ('.')
    //      character.
    // 2.   Let the Encoded JOSE Header be the portion of the JWT before the
    //      first period ('.') character.
    var end_of_jose_base64 = std.mem.indexOfScalar(u8, tokenText, '.') orelse return error.InvalidFormat;
    const jose_base64 = tokenText[0..end_of_jose_base64];

    // 3.   Base64url decode the Encoded JOSE Header following the
    //      restriction that no line breaks, whitespace, or other additional
    //      characters have been used.
    var jose_json = try allocator.alloc(u8, try base64url.Decoder.calcSizeForSlice(jose_base64));
    defer allocator.free(jose_json);
    try base64url.Decoder.decode(jose_json, jose_base64);

    // 4.   Verify that the resulting octet sequence is a UTF-8-encoded
    //      representation of a completely valid JSON object conforming to
    //      RFC 7159 [RFC7159]; let the JOSE Header be this JSON object.

    // TODO: Make sure the JSON parser confirms everything above

    var parser = std.json.Parser.init(allocator, .alloc_always);
    defer parser.deinit();

    var cty_opt = @as(?[]const u8, null);
    defer if (cty_opt) |cty| allocator.free(cty);

    var jwt_tree = try parser.parse(jose_json);
    defer jwt_tree.deinit();

    // 5.   Verify that the resulting JOSE Header includes only parameters
    //      and values whose syntax and semantics are both understood and
    //      supported or that are specified as being ignored when not
    //      understood.

    var jwt_root = jwt_tree.root;
    if (jwt_root != .object) return error.InvalidFormat;

    {
        var alg_val = jwt_root.object.get("alg") orelse return error.InvalidFormat;
        if (alg_val != .string) return error.InvalidFormat;
        const alg = std.meta.stringToEnum(Algorithm, alg_val.string) orelse return error.InvalidAlgorithm;

        // Make sure that the algorithm matches: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
        if (alg != expectedAlg) return error.InvalidAlgorithm;

        // TODO: Determine if "jku"/"jwk" need to be parsed and validated

        if (jwt_root.object.get("crit")) |crit_val| {
            if (crit_val != .array) return error.InvalidFormat;
            const crit = crit_val.array;
            if (crit.items.len == 0) return error.InvalidFormat;

            // TODO: Implement or allow extensions?
            return error.UnknownExtension;
        }
    }

    // 6.   Determine whether the JWT is a JWS or a JWE using any of the
    //      methods described in Section 9 of [JWE].

    const jwt_type = determine_jwt_type: {
        // From Section 9 of the JWE specification:
        // > o  If the object is using the JWS Compact Serialization or the JWE
        // >    Compact Serialization, the number of base64url-encoded segments
        // >    separated by period ('.') characters differs for JWSs and JWEs.
        // >    JWSs have three segments separated by two period ('.') characters.
        // >    JWEs have five segments separated by four period ('.') characters.
        switch (std.mem.count(u8, tokenText, ".")) {
            2 => break :determine_jwt_type JWTType.JWS,
            4 => break :determine_jwt_type JWTType.JWE,
            else => return error.InvalidFormat,
        }
    };

    // 7.   Depending upon whether the JWT is a JWS or JWE, there are two
    //      cases:
    const message_base64 = get_message: {
        switch (jwt_type) {
            // If the JWT is a JWS, follow the steps specified in [JWS] for
            // validating a JWS.  Let the Message be the result of base64url
            // decoding the JWS Payload.
            .JWS => {
                var section_iter = std.mem.split(u8, tokenText, ".");
                std.debug.assert(section_iter.next() != null);
                const payload_base64 = section_iter.next().?;
                const signature_base64 = section_iter.rest();

                var signature = try allocator.alloc(u8, try base64url.Decoder.calcSizeForSlice(signature_base64));
                defer allocator.free(signature);
                try base64url.Decoder.decode(signature, signature_base64);

                const gen_sig = &generate_signature(expectedAlg, signatureOptions.key, jose_base64, payload_base64);
                if (!std.mem.eql(u8, signature, gen_sig)) {
                    return error.InvalidSignature;
                }

                break :get_message try allocator.dupe(u8, payload_base64);
            },
            .JWE => {
                // Else, if the JWT is a JWE, follow the steps specified in
                // [JWE] for validating a JWE.  Let the Message be the resulting
                // plaintext.
                return error.Unimplemented;
            },
        }
    };
    defer allocator.free(message_base64);

    // 8.   If the JOSE Header contains a "cty" (content type) value of
    //      "JWT", then the Message is a JWT that was the subject of nested
    //      signing or encryption operations.  In this case, return to Step
    //      1, using the Message as the JWT.
    if (jwt_root.object.get("cty")) |cty_val| {
        if (cty_val != .string) return error.InvalidFormat;
        return error.Unimplemented;
    }

    // 9.   Otherwise, base64url decode the Message following the
    //      restriction that no line breaks, whitespace, or other additional
    //      characters have been used.
    var message = try allocator.alloc(u8, try base64url.Decoder.calcSizeForSlice(message_base64));
    errdefer allocator.free(message);
    try base64url.Decoder.decode(message, message_base64);

    return message;
}

pub fn generate_signature(comptime algo: Algorithm, key: []const u8, protectedHeaderBase64: []const u8, payloadBase64: []const u8) [algo.CryptoFn().mac_length]u8 {
    const T = algo.CryptoFn();
    var h = T.init(key);
    h.update(protectedHeaderBase64);
    h.update(".");
    h.update(payloadBase64);

    var out: [T.mac_length]u8 = undefined;
    h.final(&out);

    return out;
}

test "generate jws based tokens" {
    const payload = .{
        .sub = "1234567890",
        .name = "John Doe",
        .iat = 1516239022,
    };

    try test_generate(
        .HS256,
        payload,
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SVT7VUK8eOve-SCacPaU_bkzT3SFr9wk5EQciofG4Qo",
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
    );
    try test_generate(
        .HS384,
        payload,
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.MSnfJgb61edr7STbvEqi4Mj3Vvmb8Kh3lsnlXacv0cDAGYhBOpNmOrhWwQgTJCKj",
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
    );
    try test_generate(
        .HS512,
        payload,
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.39Xvky4dIVLaVaOW5BgbO7smTZUyvIcRtBE3i2hVW3GbjSeUFmpwRbMy94CfvgHC3KHT6V4-pnkNTotCWer-cw",
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
    );
}

test "validate jws based tokens" {
    const expected = TestValidatePayload{
        .iss = "joe",
        .exp = 1300819380,
        .@"http://example.com/is_root" = true,
    };

    try test_validate(
        .HS256,
        expected,
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
    );
    try test_validate(
        .HS384,
        expected,
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.2B5ucfIDtuSVRisXjPwZlqPAwgEicFIX7Gd2r8rlAbLukenHTW0Rbx1ca1VJSyLg",
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
    );
    try test_validate(
        .HS512,
        expected,
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.TrGchM_jCqCTAYUQlFmXt-KOyKO0O2wYYW5fUSV8jtdgqWJ74cqNA1zc9Ix7TU4qJ-Y32rKmP9Xpu99yiShx6g",
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
    );
}

test "generate and then validate jws token" {
    try test_generate_then_validate(.HS256, .{ .key = "a jws hmac sha-256 test key" });
    try test_generate_then_validate(.HS384, .{ .key = "a jws hmac sha-384 test key" });
}

const TestPayload = struct {
    sub: []const u8,
    name: []const u8,
    iat: i64,
};

fn test_generate(comptime algorithm: Algorithm, payload: TestPayload, expected: []const u8, key_base64: []const u8) !void {
    var key = try std.testing.allocator.alloc(u8, try base64url.Decoder.calcSizeForSlice(key_base64));
    defer std.testing.allocator.free(key);
    try base64url.Decoder.decode(key, key_base64);

    const token = try encode(std.testing.allocator, algorithm, payload, .{ .key = key });
    defer std.testing.allocator.free(token);

    try std.testing.expectEqualSlices(u8, expected, token);
}

const TestValidatePayload = struct {
    iss: []const u8,
    exp: i64,
    @"http://example.com/is_root": bool,
};

fn test_validate(comptime algorithm: Algorithm, expected: TestValidatePayload, token: []const u8, key_base64: []const u8) !void {
    var key = try std.testing.allocator.alloc(u8, try base64url.Decoder.calcSizeForSlice(key_base64));
    defer std.testing.allocator.free(key);
    try base64url.Decoder.decode(key, key_base64);

    var claims = try validate(TestValidatePayload, std.testing.allocator, algorithm, token, .{ .key = key });
    defer validateFree(TestValidatePayload, std.testing.allocator, claims);

    try std.testing.expectEqualSlices(u8, expected.iss, claims.iss);
    try std.testing.expectEqual(expected.exp, claims.exp);
    try std.testing.expectEqual(expected.@"http://example.com/is_root", claims.@"http://example.com/is_root");
}

fn test_generate_then_validate(comptime alg: Algorithm, signatureOptions: SignatureOptions) !void {
    const Payload = struct {
        sub: []const u8,
        name: []const u8,
        iat: i64,
    };
    const payload = Payload{
        .sub = "1234567890",
        .name = "John Doe",
        .iat = 1516239022,
    };

    const token = try encode(std.testing.allocator, alg, payload, signatureOptions);
    defer std.testing.allocator.free(token);

    var decoded = try validate(Payload, std.testing.allocator, alg, token, signatureOptions);
    defer validateFree(Payload, std.testing.allocator, decoded);

    try std.testing.expectEqualSlices(u8, payload.sub, decoded.sub);
    try std.testing.expectEqualSlices(u8, payload.name, decoded.name);
    try std.testing.expectEqual(payload.iat, decoded.iat);
}
