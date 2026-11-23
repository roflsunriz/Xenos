#pragma once

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

/// <summary>
/// AmalgamLoader-style auto-injection.
///
/// The watcher waits for a target image to start, waits until the process is
/// actually ready (required modules loaded / enough modules / N consecutive
/// stable checks), then injects with retries and exponential backoff. New
/// instances of the target are picked up as well; already injected processes
/// are skipped by the caller.
///
/// This is intentionally independent of the GUI and of InjectionCore so the
/// CLI and other front-ends can share it.
/// </summary>
namespace watch
{
    struct TargetSpec
    {
        std::wstring name;      // image name, e.g. "game.exe"
        std::wstring path;      // optional full path; empty = match by name
    };

    struct Readiness
    {
        std::vector<std::wstring> modules;  // required module substrings (all must match)
        uint32_t minModules = 0;            // minimum loaded module count (0 = disabled)
        uint32_t stableChecks = 2;          // consecutive ready checks before injecting
        uint32_t intervalMs = 500;          // readiness poll interval
        uint32_t settleMs = 0;              // extra wait after the process is stable
        uint32_t timeoutMs = 0;             // readiness timeout (0 = wait forever)
    };

    struct Retry
    {
        uint32_t attempts = 3;              // total injection attempts (>= 1)
        uint32_t baseDelayMs = 500;         // first retry delay; doubles per attempt
        uint32_t jitterMs = 100;            // random jitter added to each retry delay
    };

    struct Options
    {
        TargetSpec target;
        Readiness readiness;
        Retry retry;
        uint32_t pollMs = 1000;             // process scan interval
        uint32_t runTimeoutMs = 0;          // overall watch timeout (0 = forever)
        bool once = false;                  // stop after the first successful injection
        bool includeExisting = true;        // inject already running instances
        bool exitWhenGone = false;          // stop when no target instance remains
    };

    struct ProcessRef
    {
        DWORD        pid = 0;
        uint64_t     startTime = 0;         // FILETIME, used to detect PID reuse
        std::wstring name;
        std::wstring path;
    };

    struct Result
    {
        bool         injected = false;
        ProcessRef   process;
        std::wstring message;
    };

    using LogFn = std::function<void( const std::wstring& )>;
    using InjectFn = std::function<bool( const ProcessRef&, std::wstring& )>;

    class Watcher
    {
    public:
        Watcher( Options options, InjectFn inject, LogFn log = nullptr );
        ~Watcher();

        /// <summary>
        /// Run until canceled, the first successful injection (once), or no
        /// target is left (exitWhenGone). Returns true if at least one
        /// injection succeeded.
        /// </summary>
        bool Run();

        /// <summary>
        /// Ask Run() to stop. Safe to call from a console control handler or
        /// another thread.
        /// </summary>
        void Stop();

        const Result& LastResult() const { return _last; }

    private:
        bool Scan( std::vector<ProcessRef>& targets ) const;
        bool WaitUntilReady( const ProcessRef& target, std::wstring& reason );
        bool InjectWithRetry( const ProcessRef& target, std::wstring& message );
        bool Sleep( uint32_t ms ) const;
        bool TargetAlive( const ProcessRef& target ) const;
        void Log( const std::wstring& text ) const;

        Options _options;
        InjectFn _inject;
        LogFn _log;
        std::atomic<bool> _stop{ false };
        uint64_t _start = 0;
        Result _last;
    };

    /// <summary>
    /// Query image name, full path and creation time for a PID.
    /// </summary>
    bool QueryProcess( DWORD pid, ProcessRef& out );

    /// <summary>
    /// Check readiness: required modules, minimum module count, and that the
    /// process is still alive. Returns false and fills reason when not ready.
    /// </summary>
    bool IsProcessReady( DWORD pid, const Readiness& options, std::wstring& reason );
}
