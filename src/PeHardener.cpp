#include "PeHardener.h"

#include <windows.h>

#include <algorithm>
#include <cstddef>
#include <ctime>
#include <random>
#include <vector>

namespace peh
{
    static_assert(
        offsetof( IMAGE_OPTIONAL_HEADER32, CheckSum ) ==
        offsetof( IMAGE_OPTIONAL_HEADER64, CheckSum ),
        "PE32 and PE32+ checksum offsets must match" );

    namespace
    {
        struct Layout
        {
            size_t timestampOffset = 0;
            size_t checksumOffset = 0;
            size_t fileSize = 0;
            bool   pe64 = false;
            uint32_t oldTimestamp = 0;
        };

        std::wstring BaseName( const std::wstring& path )
        {
            const auto pos = path.find_last_of( L"\\/" );
            return pos == std::wstring::npos ? path : path.substr( pos + 1 );
        }

        std::wstring Directory( const std::wstring& path )
        {
            const auto pos = path.find_last_of( L"\\/" );
            return pos == std::wstring::npos ? L"." : path.substr( 0, pos );
        }

        bool ReadAll( const std::wstring& path, std::vector<uint8_t>& data, std::wstring& error )
        {
            HANDLE file = CreateFileW(
                path.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );

            if (file == INVALID_HANDLE_VALUE)
            {
                error = L"cannot open input (" + std::to_wstring( GetLastError() ) + L")";
                return false;
            }

            LARGE_INTEGER size = { 0 };
            if (!GetFileSizeEx( file, &size ) || size.QuadPart < 0)
            {
                error = L"cannot determine input size";
                CloseHandle( file );
                return false;
            }

            if (size.QuadPart > 512ull * 1024 * 1024)
            {
                error = L"input is larger than 512 MiB";
                CloseHandle( file );
                return false;
            }

            data.resize( static_cast<size_t>( size.QuadPart ) );

            size_t offset = 0;
            while (offset < data.size())
            {
                const DWORD chunk = static_cast<DWORD>(
                    (std::min)( data.size() - offset, static_cast<size_t>( 1 << 20 ) ) );

                DWORD read = 0;
                if (!ReadFile( file, data.data() + offset, chunk, &read, nullptr ) || read == 0)
                {
                    error = L"cannot read input";
                    CloseHandle( file );
                    return false;
                }

                offset += read;
            }

            CloseHandle( file );
            return true;
        }

        bool WriteAll( const std::wstring& path, const std::vector<uint8_t>& data, std::wstring& error )
        {
            HANDLE file = CreateFileW(
                path.c_str(), GENERIC_WRITE, 0, nullptr,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr );

            if (file == INVALID_HANDLE_VALUE)
            {
                error = L"cannot create output (" + std::to_wstring( GetLastError() ) + L")";
                return false;
            }

            size_t offset = 0;
            while (offset < data.size())
            {
                const DWORD chunk = static_cast<DWORD>(
                    (std::min)( data.size() - offset, static_cast<size_t>( 1 << 20 ) ) );

                DWORD written = 0;
                if (!WriteFile( file, data.data() + offset, chunk, &written, nullptr ) || written == 0)
                {
                    error = L"cannot write output (" + std::to_wstring( GetLastError() ) + L")";
                    CloseHandle( file );
                    DeleteFileW( path.c_str() );
                    return false;
                }

                offset += written;
            }

            if (!FlushFileBuffers( file ))
            {
                error = L"cannot flush output";
                CloseHandle( file );
                DeleteFileW( path.c_str() );
                return false;
            }

            CloseHandle( file );
            return true;
        }

        bool Parse( const std::vector<uint8_t>& data, Layout& layout, std::wstring& error )
        {
            layout = Layout();
            layout.fileSize = data.size();

            if (data.size() < sizeof( IMAGE_DOS_HEADER ))
            {
                error = L"not a PE file (truncated DOS header)";
                return false;
            }

            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>( data.data() );
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            {
                error = L"not a PE file (invalid DOS signature)";
                return false;
            }

            const size_t ntOffset = static_cast<size_t>( dos->e_lfanew );
            if (ntOffset < sizeof( IMAGE_DOS_HEADER ) ||
                ntOffset + sizeof( DWORD ) + sizeof( IMAGE_FILE_HEADER ) > data.size())
            {
                error = L"invalid NT header offset";
                return false;
            }

            const DWORD signature = *reinterpret_cast<const DWORD*>( data.data() + ntOffset );
            if (signature != IMAGE_NT_SIGNATURE)
            {
                error = L"invalid NT signature";
                return false;
            }

            const size_t fileHeaderOffset = ntOffset + sizeof( DWORD );
            const auto* file = reinterpret_cast<const IMAGE_FILE_HEADER*>(
                data.data() + fileHeaderOffset );

            const size_t optionalOffset = fileHeaderOffset + sizeof( IMAGE_FILE_HEADER );
            if (optionalOffset + sizeof( WORD ) > data.size())
            {
                error = L"truncated optional header";
                return false;
            }

            const WORD magic = *reinterpret_cast<const WORD*>( data.data() + optionalOffset );
            if (magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                error = L"unknown optional header magic";
                return false;
            }

            layout.pe64 = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

            const size_t minimumOptional = layout.pe64 ?
                sizeof( IMAGE_OPTIONAL_HEADER64 ) : sizeof( IMAGE_OPTIONAL_HEADER32 );

            if (file->SizeOfOptionalHeader < minimumOptional ||
                optionalOffset + file->SizeOfOptionalHeader > data.size())
            {
                error = L"invalid optional header size";
                return false;
            }

            const size_t sectionOffset = optionalOffset + file->SizeOfOptionalHeader;
            const size_t sectionBytes =
                static_cast<size_t>( file->NumberOfSections ) * sizeof( IMAGE_SECTION_HEADER );

            if (sectionOffset + sectionBytes > data.size())
            {
                error = L"truncated section table";
                return false;
            }

            const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
                data.data() + sectionOffset );

            for (WORD i = 0; i < file->NumberOfSections; i++)
            {
                const uint64_t end =
                    static_cast<uint64_t>( sections[i].PointerToRawData ) +
                    sections[i].SizeOfRawData;

                if (end > data.size())
                {
                    error = L"section " + std::to_wstring( i ) + L" extends past end of file";
                    return false;
                }
            }

            layout.timestampOffset = fileHeaderOffset + offsetof( IMAGE_FILE_HEADER, TimeDateStamp );
            layout.checksumOffset = optionalOffset + offsetof( IMAGE_OPTIONAL_HEADER64, CheckSum );
            layout.oldTimestamp = file->TimeDateStamp;

            return true;
        }

        uint32_t CalculateChecksum( const std::vector<uint8_t>& data, size_t checksumOffset )
        {
            uint64_t sum = 0;

            for (size_t i = 0; i < data.size(); i += 2)
            {
                // The checksum field itself is treated as zero.
                if (i >= checksumOffset && i < checksumOffset + 4)
                    continue;

                uint32_t word = data[i];
                if (i + 1 < data.size())
                    word |= static_cast<uint32_t>( data[i + 1] ) << 8;

                sum += word;
                sum = (sum & 0xffff) + (sum >> 16);
            }

            sum = (sum & 0xffff) + (sum >> 16);
            sum = (sum & 0xffff) + (sum >> 16);

            return static_cast<uint32_t>( sum + data.size() );
        }

        DWORD MakeTimestamp( DWORD oldTimestamp )
        {
            std::random_device device;
            std::mt19937_64 rng(
                static_cast<uint64_t>( device() ) ^
                static_cast<uint64_t>( GetTickCount64() ) ^
                static_cast<uint64_t>( GetCurrentProcessId() ) );

            std::uniform_int_distribution<int> days( 180, 730 );
            std::uniform_int_distribution<int> hours( 0, 23 );
            std::uniform_int_distribution<int> minutes( 0, 59 );

            const std::time_t now = std::time( nullptr );
            std::time_t value = now -
                static_cast<std::time_t>( days( rng ) ) * 24 * 60 * 60 -
                static_cast<std::time_t>( hours( rng ) ) * 60 * 60 -
                static_cast<std::time_t>( minutes( rng ) ) * 60;

            DWORD result = static_cast<DWORD>( value );
            if (result == oldTimestamp)
                result++;

            return result;
        }

        bool SameFile( const std::wstring& left, const std::wstring& right )
        {
            wchar_t leftFull[MAX_PATH * 2] = { 0 };
            wchar_t rightFull[MAX_PATH * 2] = { 0 };

            const DWORD leftLength = GetFullPathNameW(
                left.c_str(), ARRAYSIZE( leftFull ), leftFull, nullptr );
            const DWORD rightLength = GetFullPathNameW(
                right.c_str(), ARRAYSIZE( rightFull ), rightFull, nullptr );

            if (leftLength == 0 || rightLength == 0)
                return _wcsicmp( left.c_str(), right.c_str() ) == 0;

            return _wcsicmp( leftFull, rightFull ) == 0;
        }

        std::wstring DefaultOutput( const std::wstring& input )
        {
            const std::wstring name = BaseName( input );
            const auto dot = name.find_last_of( L'.' );
            const std::wstring stem = dot == std::wstring::npos ? name : name.substr( 0, dot );
            const std::wstring extension = dot == std::wstring::npos ? L"" : name.substr( dot );

            return Directory( input ) + L"\\" + stem + L".hardened" + extension;
        }
    }

    bool Harden( const std::wstring& inputPath, const Options& options, Result& result )
    {
        result = Result();
        result.inputPath = inputPath;

        std::vector<uint8_t> data;
        if (!ReadAll( inputPath, data, result.message ))
            return false;

        result.oldSize = data.size();

        Layout layout;
        if (!Parse( data, layout, result.message ))
            return false;

        result.oldTimestamp = layout.oldTimestamp;

        // 1. Timestamp: avoid the "freshly compiled" build time without
        //    touching code or resources.
        if (options.timestamp)
        {
            const DWORD timestamp = MakeTimestamp( layout.oldTimestamp );
            *reinterpret_cast<DWORD*>( data.data() + layout.timestampOffset ) = timestamp;
            result.newTimestamp = timestamp;
        }
        else
        {
            result.newTimestamp = layout.oldTimestamp;
        }

        // 2. Overlay: random bytes after the last section. This changes the
        //    file hash without invalidating any RVA in the image.
        const uint32_t overlay = (std::min)( options.overlayBytes, 16u * 1024 * 1024 );
        result.overlayBytes = overlay;

        if (overlay != 0)
        {
            const size_t oldSize = data.size();
            data.resize( oldSize + overlay );

            std::random_device device;
            std::mt19937 rng(
                device() ^ static_cast<uint32_t>( GetTickCount64() ) ^
                static_cast<uint32_t>( GetCurrentProcessId() ) );

            for (size_t i = oldSize; i < data.size(); i++)
                data[i] = static_cast<uint8_t>( rng() & 0xff );
        }

        // 3. Keep the checksum coherent when the image has one.
        const uint32_t oldChecksum =
            *reinterpret_cast<const uint32_t*>( data.data() + layout.checksumOffset );

        if (oldChecksum != 0)
        {
            const uint32_t checksum = CalculateChecksum( data, layout.checksumOffset );
            *reinterpret_cast<uint32_t*>( data.data() + layout.checksumOffset ) = checksum;
        }

        // 4. Validate the transformed image before writing anything.
        Layout validation;
        if (!Parse( data, validation, result.message ))
        {
            result.message = L"internal validation failed: " + result.message;
            return false;
        }

        result.newSize = data.size();

        // 5. Choose the output path. In-place mode is explicit and refuses to
        //    modify the currently running executable.
        std::wstring output = options.inPlace ? inputPath :
            (options.output.empty() ? DefaultOutput( inputPath ) : options.output);

        if (!options.inPlace && SameFile( inputPath, output ))
            output = DefaultOutput( inputPath );

        wchar_t self[MAX_PATH * 2] = { 0 };
        if (GetModuleFileNameW( nullptr, self, ARRAYSIZE( self ) ) != 0 &&
            SameFile( self, output ))
        {
            result.message = L"refusing to modify the currently running executable";
            return false;
        }

        if (!options.force && GetFileAttributesW( output.c_str() ) != INVALID_FILE_ATTRIBUTES &&
            !SameFile( inputPath, output ))
        {
            result.message = L"output already exists (use --force to overwrite): " + output;
            return false;
        }

        const std::wstring temp = output + L".tmp" + std::to_wstring( GetCurrentProcessId() );

        if (!WriteAll( temp, data, result.message ))
            return false;

        if (!MoveFileExW( temp.c_str(), output.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH ))
        {
            result.message = L"cannot move output into place (" +
                std::to_wstring( GetLastError() ) + L")";
            DeleteFileW( temp.c_str() );
            return false;
        }

        result.outputPath = output;
        result.ok = true;
        result.message = L"timestamp " + std::to_wstring( result.oldTimestamp ) + L" -> " +
            std::to_wstring( result.newTimestamp ) + L", overlay " +
            std::to_wstring( result.overlayBytes ) + L" bytes";
        return true;
    }
}
