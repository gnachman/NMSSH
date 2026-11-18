//
//  SSHConfigResolver.swift
//  NMSSH
//
//  Resolves the ssh_config settings NMSSH uses (HostName, User, Port, IdentityFile) for a
//  host, following OpenSSH's readconf.c (revision 1.424) and the config passes in ssh.c.
//  Derived from OpenSSH; modified from the original by porting it to Swift, reading only a
//  few settings, and treating configuration errors leniently (see below). Function-level
//  comments name the upstream function each part follows.
//
//  Original notice from readconf.c:
//
//  Author: Tatu Ylonen <ylo@cs.hut.fi>
//  Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
//                     All rights reserved
//  Functions for reading the configuration files.
//
//  As far as I am concerned, the code I have written for this software
//  can be used freely for any purpose.  Any derived versions of this
//  software must be clearly marked as such, and if the derived work is
//  incompatible with the protocol description in the RFC file, it must be
//  called by a name other than "ssh" or "Secure Shell".
//
//  Differences from OpenSSH, all deliberate:
//
//  - Errors are not fatal. A line OpenSSH would reject is skipped and logged, except that a
//    Host or Match line it would reject makes its block inactive. An Include that can't be
//    expanded, is nested too deeply, or names a file with unsafe ownership or permissions is
//    skipped.
//  - A Host argument containing a comma is treated as a pattern list, as NMSSH always has.
//  - Match exec never matches (negated or not), because running commands to look up a host
//    name is unsafe. Match localnetwork and Match version are not supported either and also
//    never match.
//  - Hostname canonicalization does no DNS lookups. CanonicalizeHostname still triggers the
//    second ("final") pass, as in OpenSSH, so Match canonical and Match final blocks apply.
//  - The %C, %j, and %k tokens are not supported in Include paths; such an Include is skipped.
//  - IdentityFile paths get ~ expanded but not %-tokens.
//

import Darwin
import Foundation

/// One top-level ssh config file to read.
@objc(NMSSHConfigFile)
public final class SSHConfigFile: NSObject {
    @objc public let path: String

    /// A user config (such as ~/.ssh/config) may use `~` in Include paths and resolves
    /// relative ones under ~/.ssh. A system config resolves them under /etc/ssh.
    @objc public let isUserConfig: Bool

    @objc public init(path: String, isUserConfig: Bool) {
        self.path = path
        self.isUserConfig = isUserConfig
    }
}

/// Reads a list of ssh config files as OpenSSH would for one connection.
@objc(NMSSHConfigResolver)
public final class SSHConfigResolver: NSObject {
    /// Facts about the local system that config evaluation depends on. Tests substitute
    /// their own.
    public struct LocalSystem {
        public var homeDirectory: String
        public var userName: String
        public var uid: uid_t
        public var hostname: String
        public var environment: [String: String]
        /// Where a system config's relative Include paths are resolved (SSHDIR).
        public var systemConfigDirectory: String

        public init(homeDirectory: String,
                    userName: String,
                    uid: uid_t,
                    hostname: String,
                    environment: [String: String],
                    systemConfigDirectory: String = "/etc/ssh") {
            self.homeDirectory = homeDirectory
            self.userName = userName
            self.uid = uid
            self.hostname = hostname
            self.environment = environment
            self.systemConfigDirectory = systemConfigDirectory
        }

        public static var current: LocalSystem {
            var buffer = [CChar](repeating: 0, count: Int(MAXHOSTNAMELEN) + 1)
            let hostname = gethostname(&buffer, buffer.count) == 0 ? String(cString: buffer) : ""
            return LocalSystem(homeDirectory: NSHomeDirectory(),
                               userName: NSUserName(),
                               uid: getuid(),
                               hostname: hostname,
                               environment: ProcessInfo.processInfo.environment)
        }
    }

    /// READCONF_MAX_DEPTH.
    static let maximumIncludeDepth = 16

    /// Not in OpenSSH: a bound on how many files one lookup reads, so a glob or include cycle
    /// can't make a lookup arbitrarily slow.
    static let maximumFilesRead = 1000

    fileprivate let files: [SSHConfigFile]
    fileprivate let localSystem: LocalSystem

    /// Called with a description of each problem found in the config, such as a skipped line.
    @objc public var logHandler: ((String) -> Void)?

    @objc public convenience init(files: [SSHConfigFile]) {
        self.init(files: files, localSystem: .current)
    }

    public init(files: [SSHConfigFile], localSystem: LocalSystem) {
        self.files = files
        self.localSystem = localSystem
    }

    /// The settings for connecting to `host`. A non-nil `user` or `port` is one given
    /// explicitly (as with `ssh -l` or `-p`), so it takes precedence over the config, as in
    /// OpenSSH. The result's hostname is nil when no HostName applies.
    @objc(hostConfigForHost:user:port:)
    public func hostConfig(forHost host: String, user: String?, port: NSNumber?) -> NMSSHHostConfig {
        return resolve(host: host, user: user, port: port?.intValue, remoteCommand: nil)
    }

    /// Like hostConfig(forHost:user:port:), and also takes the remote command for
    /// Match command and Match sessiontype.
    public func resolve(host: String, user: String?, port: Int?, remoteCommand: String?) -> NMSSHHostConfig {
        var evaluation = Evaluation(resolver: self,
                                    originalHost: host,
                                    remoteCommand: remoteCommand)
        evaluation.options.user = user
        evaluation.options.port = port
        evaluation.run()

        let result = NMSSHHostConfig()
        result.hostname = evaluation.resolvedHostname
        result.user = evaluation.options.user
        result.port = evaluation.options.port.map { NSNumber(value: $0) }
        result.identityFiles = evaluation.options.identityFiles
        return result
    }

    fileprivate func log(_ message: String) {
        logHandler?(message)
    }
}

// MARK: - Evaluation

/// The settings read so far. As in OpenSSH, the first value obtained for each wins.
private struct Options {
    var hostname: String?
    var user: String?
    var port: Int?
    var identityFiles = [String]()
    var tag: String?
    /// SSH_CANONICALISE_NO (0), _YES (1), or _ALWAYS (2).
    var canonicalizeHostname: Int?
}

private struct ReadFlags: OptionSet {
    let rawValue: Int
    /// SSHCONF_USERCONF
    static let userConfig = ReadFlags(rawValue: 1 << 0)
    /// SSHCONF_CHECKPERM
    static let checkPermissions = ReadFlags(rawValue: 1 << 1)
    /// SSHCONF_NEVERMATCH
    static let neverMatch = ReadFlags(rawValue: 1 << 2)
    /// SSHCONF_FINAL
    static let finalPass = ReadFlags(rawValue: 1 << 3)
}

/// One lookup: the state OpenSSH keeps in `options`, `host`, and `want_final_pass`.
private struct Evaluation {
    let resolver: SSHConfigResolver
    /// The host as given (host_arg / original_host).
    let originalHost: String
    let remoteCommand: String?
    var options = Options()
    /// The global `host` in ssh.c: the host as given during the first pass, then the
    /// resolved host name during the final pass.
    var currentHost: String
    var wantFinalPass = false
    var filesRead = 0
    /// The host name ssh would connect to, when a HostName applied.
    var resolvedHostname: String?

    private var local: SSHConfigResolver.LocalSystem { resolver.localSystem }

    init(resolver: SSHConfigResolver, originalHost: String, remoteCommand: String?) {
        self.resolver = resolver
        self.originalHost = originalHost
        self.remoteCommand = remoteCommand
        self.currentHost = originalHost
    }

    /// Follows main() in ssh.c from the first process_config_files() through the final pass.
    mutating func run() {
        processConfigFiles(finalPass: false)

        var host = currentHost
        if let hostname = options.hostname {
            // NB. Please keep in sync with readconf.c:match_cfg_line()
            host = expand(hostname, hostToken: currentHost)
            options.hostname = host
        }
        if !isAddress(host) {
            host = asciiLowercased(host)
        }
        let hostnameConfigured = options.hostname != nil
        if (options.canonicalizeHostname ?? 0) != 0 && !wantFinalPass {
            wantFinalPass = true
        }
        if wantFinalPass {
            options.hostname = host
            currentHost = host
            processConfigFiles(finalPass: true)
        }
        if hostnameConfigured {
            resolvedHostname = host
        }
    }

    /// Follows process_config_files() in ssh.c, reading each top-level file in order.
    private mutating func processConfigFiles(finalPass: Bool) {
        for file in resolver.files {
            var flags: ReadFlags = finalPass ? [.finalPass] : []
            if file.isUserConfig {
                flags.insert(.userConfig)
            }
            var active = true
            _ = readConfigFile(file.path, flags: flags, active: &active, depth: 0)
        }
    }

    /// Follows read_config_file_depth(). Returns false if the file couldn't be read.
    private mutating func readConfigFile(_ path: String,
                                         flags: ReadFlags,
                                         active: inout Bool,
                                         depth: Int) -> Bool {
        if depth > SSHConfigResolver.maximumIncludeDepth {
            resolver.log("\(path): too many nested includes; skipping")
            return false
        }
        if filesRead >= SSHConfigResolver.maximumFilesRead {
            resolver.log("\(path): read \(filesRead) config files already; skipping")
            return false
        }
        guard let data = FileManager.default.contents(atPath: path) else {
            if FileManager.default.fileExists(atPath: path) {
                resolver.log("\(path): can't read config file")
            }
            return false
        }
        filesRead += 1
        if flags.contains(.checkPermissions) && !hasSafeOwnershipAndPermissions(path) {
            resolver.log("\(path): bad owner or permissions; skipping")
            return false
        }

        var lineNumber = 0
        for line in data.split(separator: UInt8(ascii: "\n"), omittingEmptySubsequences: false) {
            lineNumber += 1
            processConfigLine(Array(line),
                              filename: path,
                              lineNumber: lineNumber,
                              flags: flags,
                              active: &active,
                              depth: depth)
        }
        return true
    }

    /// The check read_config_file_depth() makes with SSHCONF_CHECKPERM.
    private func hasSafeOwnershipAndPermissions(_ path: String) -> Bool {
        var sb = stat()
        guard stat(path, &sb) == 0 else {
            return false
        }
        return (sb.st_uid == 0 || sb.st_uid == getuid()) && (sb.st_mode & 0o022) == 0
    }

    // MARK: - Lines

    /// Follows process_config_line_depth() for the keywords NMSSH reads.
    private mutating func processConfigLine(_ rawLine: [UInt8],
                                            filename: String,
                                            lineNumber: Int,
                                            flags: ReadFlags,
                                            active: inout Bool,
                                            depth: Int) {
        let complain: (String) -> Void = { [resolver] message in
            resolver.log("\(filename) line \(lineNumber): \(message)")
        }

        // Strip trailing whitespace. Allow \f (form feed) at EOL only.
        var line = rawLine
        while line.count > 1, let last = line.last,
              SSHConfigTokenizer.isWhitespace(last) || last == 0x0c {
            line.removeLast()
        }
        if line.isEmpty {
            return
        }

        var cursor = SSHConfigTokenizer.Cursor(line)
        guard var keywordBytes = cursor.next() else {
            return
        }
        // Ignore leading whitespace.
        if keywordBytes.isEmpty {
            guard let next = cursor.next() else {
                return
            }
            keywordBytes = next
        }
        if keywordBytes.isEmpty || keywordBytes[0] == UInt8(ascii: "\n") || keywordBytes[0] == UInt8(ascii: "#") {
            return
        }
        let keyword = asciiLowercased(String(decoding: keywordBytes, as: UTF8.self))

        guard var rest = cursor.remainder else {
            complain("no argument after keyword “\(keyword)”")
            return
        }
        rest = Array(rest[SSHConfigTokenizer.skippingWhitespace(rest, from: 0)...])
        if rest.isEmpty {
            complain("no argument after keyword “\(keyword)”")
            return
        }
        guard let args = SSHConfigTokenizer.splitArguments(rest, terminateOnComment: true)?
            .map({ String(decoding: $0, as: UTF8.self) }) else {
            complain("invalid quotes")
            if keyword == "host" || keyword == "match" {
                // Not in OpenSSH, where this is fatal. Skipping the line would apply the
                // block's settings to whatever came before it, possibly every host, so treat
                // the block as not matching instead.
                active = false
            }
            return
        }

        switch keyword {
        case "host":
            processHost(args, flags: flags, active: &active, complain: complain)

        case "match":
            switch matchConfigLine(args, flags: flags, complain: complain) {
            case .none:
                complain("bad Match condition; treating its block as not matching")
                active = false
            case .some(let matched):
                active = flags.contains(.neverMatch) ? false : matched
            }

        case "include":
            processInclude(args,
                           filename: filename,
                           flags: flags,
                           active: &active,
                           depth: depth,
                           complain: complain)

        case "hostname":
            if let value = stringArgument(args, complain), active, options.hostname == nil {
                options.hostname = value
            }

        case "user":
            if let value = stringArgument(args, complain), active, options.user == nil {
                options.user = value
            }

        case "tag":
            if let value = stringArgument(args, complain), active, options.tag == nil {
                options.tag = value
            }

        case "port":
            guard let arg = stringArgument(args, complain) else {
                return
            }
            let value = parsePort(arg)
            if value <= 0 {
                complain("bad port “\(arg)”")
                return
            }
            if active && options.port == nil {
                options.port = value
            }

        case "identityfile":
            if let value = stringArgument(args, complain), active {
                addIdentityFile(value)
            }

        case "canonicalizehostname":
            guard let arg = stringArgument(args, complain) else {
                return
            }
            let states = ["true": 1, "false": 0, "yes": 1, "no": 0, "always": 2]
            guard let value = states[asciiLowercased(arg)] else {
                complain("unsupported option “\(arg)”")
                return
            }
            if active && options.canonicalizeHostname == nil {
                options.canonicalizeHostname = value
            }

        default:
            // Settings NMSSH doesn't use.
            break
        }
    }

    /// The first argument, as parse_string reads it.
    private func stringArgument(_ args: [String], _ complain: (String) -> Void) -> String? {
        guard let arg = args.first, !arg.isEmpty else {
            complain("missing argument")
            return nil
        }
        return arg
    }

    /// Follows case oHost. A Host line starts a block that applies if any pattern matches the
    /// host and no negated one does.
    private func processHost(_ args: [String],
                             flags: ReadFlags,
                             active: inout Bool,
                             complain: (String) -> Void) {
        active = false
        for arg in args {
            if arg.isEmpty {
                complain("keyword host empty argument")
                return
            }
            if flags.contains(.neverMatch) {
                break
            }
            if arg.contains(",") {
                // Not in OpenSSH: NMSSH has always treated a comma-separated Host argument
                // as a pattern list.
                switch SSHConfigPattern.matchesList(currentHost, patternList: arg, lowercasePattern: false) {
                case .negative:
                    active = false
                    return
                case .positive:
                    active = true
                case .none:
                    break
                }
                continue
            }
            let negated = arg.hasPrefix("!")
            let pattern = negated ? String(arg.dropFirst()) : arg
            if SSHConfigPattern.matches(currentHost, pattern: pattern) {
                if negated {
                    active = false
                    return
                }
                active = true
            }
        }
    }

    /// Follows add_identity_file(), ignoring duplicates.
    private mutating func addIdentityFile(_ value: String) {
        let path = expandTilde(value) ?? value
        if !options.identityFiles.contains(path) {
            options.identityFiles.append(path)
        }
    }

    // MARK: - Match

    /// Follows match_cfg_line(). Returns nil for a malformed line, which OpenSSH rejects.
    private mutating func matchConfigLine(_ args: [String],
                                          flags: ReadFlags,
                                          complain: (String) -> Void) -> Bool? {
        let finalPass = flags.contains(.finalPass)
        let ruser = options.user ?? local.userName
        let host: String
        if finalPass {
            host = options.hostname ?? currentHost
        } else if let hostname = options.hostname {
            // NB. Please keep in sync with ssh.c:main()
            host = expand(hostname, hostToken: currentHost)
        } else {
            host = currentHost
        }

        var result = true
        var attributes = 0
        var i = 0
        func nextArg() -> String? {
            guard i < args.count else {
                return nil
            }
            defer { i += 1 }
            return args[i]
        }

        while let rawAttribute = nextArg() {
            // Terminate on comment.
            if rawAttribute.hasPrefix("#") {
                break
            }
            let negate = rawAttribute.hasPrefix("!")
            var attribute = negate ? String(rawAttribute.dropFirst()) : rawAttribute
            let lowered = asciiLowercased(attribute)

            // Criterion "all" has no argument and must appear alone.
            if lowered == "all" {
                if attributes > 1 {
                    complain("“\(rawAttribute)” cannot be combined with other Match attributes")
                    return nil
                }
                if let arg = nextArg(), !arg.isEmpty, !arg.hasPrefix("#") {
                    complain("“\(rawAttribute)” cannot be combined with other Match attributes")
                    return nil
                }
                if result {
                    result = !negate
                }
                return result
            }
            attributes += 1

            // Criteria "final" and "canonical" have no argument.
            if lowered == "canonical" || lowered == "final" {
                if lowered == "final" && !negate {
                    wantFinalPass = true
                }
                if finalPass == negate {
                    result = false
                }
                continue
            }

            var arg: String?
            let attachedArgumentPrefixes = ["host=", "originalhost=", "user=", "localuser=",
                                            "localnetwork=", "version=", "tagged=", "command=",
                                            "exec="]
            if attachedArgumentPrefixes.contains(where: { lowered.hasPrefix($0) }),
               let equals = attribute.firstIndex(of: "=") {
                arg = String(attribute[attribute.index(after: equals)...])
                attribute = String(attribute[..<equals])
            } else {
                arg = nextArg()
                if arg == nil {
                    complain("missing argument for Match “\(rawAttribute)”")
                    return nil
                }
            }
            let name = asciiLowercased(attribute)

            // All other criteria require an argument, though it may be the empty string for
            // the "tagged" and "command" options.
            if arg == "" && name != "tagged" && name != "command" {
                arg = nil
            }
            guard let arg, !arg.hasPrefix("#") else {
                complain("missing Match criteria for \(attribute)")
                return nil
            }

            let matched: Bool
            switch name {
            case "host":
                matched = SSHConfigPattern.matchesHostname(host, patternList: arg) == .positive
            case "originalhost":
                matched = SSHConfigPattern.matchesHostname(originalHost, patternList: arg) == .positive
            case "user":
                matched = SSHConfigPattern.matchesList(ruser, patternList: arg, lowercasePattern: false) == .positive
            case "localuser":
                matched = SSHConfigPattern.matchesList(local.userName, patternList: arg, lowercasePattern: false) == .positive
            case "tagged":
                matched = matchesAllowingEmpty(options.tag ?? "", arg)
            case "command":
                matched = matchesAllowingEmpty(remoteCommand ?? "", arg)
            case "sessiontype":
                let criteria = (remoteCommand ?? "").isEmpty ? "shell" : "exec"
                matched = SSHConfigPattern.matchesList(criteria, patternList: arg, lowercasePattern: false) == .positive
            case "exec", "localnetwork", "version":
                complain("Match \(name) is not supported; treating its block as not matching")
                result = false
                continue
            default:
                complain("unsupported Match attribute \(attribute)")
                return nil
            }
            if matched == negate {
                result = false
            }
        }
        if attributes == 0 {
            complain("one or more attributes required for Match")
            return nil
        }
        return result
    }

    /// Match tagged and Match command: an empty criterion matches only an empty argument.
    private func matchesAllowingEmpty(_ criteria: String, _ arg: String) -> Bool {
        if criteria.isEmpty {
            return arg.isEmpty
        }
        return SSHConfigPattern.matchesList(criteria, patternList: arg, lowercasePattern: false) == .positive
    }

    // MARK: - Include

    /// Follows case oInclude.
    private mutating func processInclude(_ args: [String],
                                         filename: String,
                                         flags: ReadFlags,
                                         active: inout Bool,
                                         depth: Int,
                                         complain: (String) -> Void) {
        for arg in args {
            if arg.isEmpty {
                complain("keyword include empty argument")
                return
            }
            // Expand %tokens and environment variables.
            guard let expanded = expandIncludePath(arg, finalPass: flags.contains(.finalPass)) else {
                complain("unable to expand include path “\(arg)”; skipping it")
                continue
            }
            // Ensure all paths are anchored. User configuration files may begin with '~/'
            // but system configurations must not. If the path is relative, then treat it as
            // living in ~/.ssh for user configurations or /etc/ssh for system ones.
            if expanded.hasPrefix("~") && !flags.contains(.userConfig) {
                complain("bad include path \(expanded)")
                return
            }
            var anchored = expanded
            if !expanded.hasPrefix("/") && !expanded.hasPrefix("~") {
                let directory = flags.contains(.userConfig) ? "~/.ssh" : local.systemConfigDirectory
                anchored = directory + "/" + expanded
            }
            guard let pattern = expandTilde(anchored) else {
                complain("unable to expand “\(anchored)”; skipping it")
                continue
            }
            guard let paths = glob(pattern) else {
                complain("glob failed for \(pattern)")
                return
            }
            let outerActive = active
            for path in paths {
                var includedFlags = flags.union(.checkPermissions)
                if !outerActive {
                    includedFlags.insert(.neverMatch)
                }
                _ = readConfigFile(path, flags: includedFlags, active: &active, depth: depth + 1)
                // Don't let Match in includes clobber the containing file's Match state.
                active = outerActive
            }
        }
    }

    /// The paths matching a glob pattern, sorted; empty when nothing matches; nil on error.
    private func glob(_ pattern: String) -> [String]? {
        var g = glob_t()
        defer {
            globfree(&g)
        }
        let r = Darwin.glob(pattern, 0, nil, &g)
        if r == GLOB_NOMATCH {
            return []
        }
        if r != 0 {
            return nil
        }
        return (0..<Int(g.gl_pathc)).compactMap { i in
            g.gl_pathv[i].map { String(cString: $0) }
        }
    }

    /// Follows expand_match_exec_or_include_path() for an Include path.
    private func expandIncludePath(_ path: String, finalPass: Bool) -> String? {
        let port = options.port ?? 22
        let ruser = options.user ?? local.userName
        let host: String
        if finalPass {
            host = options.hostname ?? currentHost
        } else if let hostname = options.hostname {
            host = expand(hostname, hostToken: currentHost)
        } else {
            host = currentHost
        }
        let shortHost = String(local.hostname.prefix(while: { $0 != "." }))
        let tokens: KeyValuePairs<String, String> = [
            "L": shortHost,
            "d": local.homeDirectory,
            "h": host,
            "l": local.hostname,
            "n": originalHost,
            "p": String(port),
            "r": ruser,
            "u": local.userName,
            "i": String(local.uid),
        ]
        switch SSHConfigExpansion.expand(path, percentTokens: tokens, environment: local.environment) {
        case .success(let value):
            return value
        case .failure:
            return nil
        }
    }

    // MARK: - Helpers

    /// Expands %h in a HostName, as ssh.c does after the first pass. OpenSSH treats a bad
    /// token as fatal; this uses the value unexpanded.
    private func expand(_ hostname: String, hostToken: String) -> String {
        if case .success(let value) = SSHConfigExpansion.expand(hostname, percentTokens: ["h": hostToken]) {
            return value
        }
        return hostname
    }

    /// Expands a leading `~` or `~user`, like tilde_expand(). Returns nil for an unknown user.
    private func expandTilde(_ path: String) -> String? {
        guard path.hasPrefix("~") else {
            return path
        }
        let afterTilde = path.dropFirst()
        let slash = afterTilde.firstIndex(of: "/") ?? afterTilde.endIndex
        let userPart = afterTilde[..<slash]
        let remainder = afterTilde[slash...]
        let home: String
        if userPart.isEmpty {
            home = local.homeDirectory
        } else {
            guard let pw = getpwnam(String(userPart)), let dir = pw.pointee.pw_dir else {
                return nil
            }
            home = String(cString: dir)
        }
        if remainder.isEmpty {
            return home
        }
        return (home.hasSuffix("/") ? String(home.dropLast()) : home) + remainder
    }

    /// Follows a2port(): a decimal port, or a TCP service name. Returns -1 if neither.
    private func parsePort(_ s: String) -> Int {
        if let value = Int(s), value >= 0, value <= 65535 {
            return value
        }
        if let se = getservbyname(s, "tcp") {
            return Int(UInt16(bigEndian: UInt16(truncatingIfNeeded: se.pointee.s_port)))
        }
        return -1
    }

    /// Follows is_addr() in ssh.c: whether `name` is a numeric IPv4 or IPv6 address.
    private func isAddress(_ name: String) -> Bool {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(name, "22", &hints, &res) == 0 else {
            return false
        }
        freeaddrinfo(res)
        return true
    }

    private func asciiLowercased(_ s: String) -> String {
        return String(decoding: s.utf8.map(SSHConfigPattern.asciiLowercased), as: UTF8.self)
    }
}
