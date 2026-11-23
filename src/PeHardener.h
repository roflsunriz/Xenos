#pragma once

#include <cstdint>
#include <string>

/// <summary>
/// Safe PE fingerprint randomization, inspired by AmalgamLoader's
/// SignatureRandomizer/TimestampRandomizer.
///
/// Unlike the original implementation this never patches code or resource
/// sections. It only:
///   * writes a randomized, plausible TimeDateStamp
///   * appends a randomized overlay (changes the file hash)
///   * recomputes the optional-header checksum when one is present
///
/// The result is validated as a PE before it is moved over the output file.
/// </summary>
namespace peh
{
    struct Options
    {
        bool         timestamp = true;       // randomize FileHeader.TimeDateStamp
        uint32_t     overlayBytes = 1024;    // random bytes appended (0 = none)
        bool         inPlace = false;        // replace the input file
        bool         force = false;          // overwrite an existing output file
        std::wstring output;                 // explicit output path (optional)
    };

    struct Result
    {
        bool         ok = false;
        std::wstring message;
        std::wstring inputPath;
        std::wstring outputPath;
        uint32_t     oldTimestamp = 0;
        uint32_t     newTimestamp = 0;
        uint64_t     oldSize = 0;
        uint64_t     newSize = 0;
        uint32_t     overlayBytes = 0;
    };

    /// <summary>
    /// Harden a PE file. Returns false and fills result.message on failure.
    /// The input is never touched unless options.inPlace is true.
    /// </summary>
    bool Harden( const std::wstring& inputPath, const Options& options, Result& result );
}
