/**
 * @file ts_vfs.h
 * @brief Single-header virtual filesystem with explicit mount points and provider descriptors.
 *
 * @author Charles 'xtrium' Riffaud-Declercq
 * @license CC BY-SA 4.0 - https://creativecommons.org/licenses/by-sa/4.0/
 *
 * Usage:
 *   Define TS_VFS_IMPLEMENTATION in exactly one translation unit before including this header.
 *
 * Example:
 * @code
 *   #define TS_VFS_IMPLEMENTATION
 *   #include <ts/ts_vfs.h>
 *
 *   ts::Vfs vfs;
 *
 *   auto file = vfs.Open("/assets/textures/hero.png").value();
 *   // Use whatever library you want to access the data
 *
 *   // Or just read the whole thing.
 *   auto bytes = vfs.Open("/shaders/main.spv")
 *       .and_then([](ts::VfsFile f) { return f.ReadBytes(); })
 *       .value();
 * 
 *   auto text = vfs.Open("/config/game.json")
 *       .and_then([](ts::VfsFile f) { return f.ReadText(); })
 *       .value();
 * @endcode
 */

#ifndef TS_VFS_H
#define TS_VFS_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <vector>

namespace ts
{
    /**
     * @brief Discriminant for VFS failures.
     *
     * Lets callers branch on the failure reason without parsing strings.
     */
    enum class EVfsErrorCode
    {
        NotFound,         ///< Path does not exist in any mounted provider.
        NotAFile,         ///< Path exists but is a directory, not a file.
        NotADirectory,    ///< Path exists but is a file, not a directory.
        MountConflict,    ///< A mount point, real directory, or real file already occupies that name.
        PermissionDenied, ///< The underlying provider refused access.
        ProviderError,    ///< The provider reported an unspecified internal failure.
    };

    /**
     * @brief Rich error type returned by VFS operations.
     *
     * Carry both a machine-readable @p code and a human-readable @p message.
     * The message is suitable for logging; the code is suitable for programmatic handling.
     */
    struct VfsError
    {
        using value_type = VfsError;

        EVfsErrorCode code;
        std::string   message;
    };

    // Convenience alias used throughout the public API.
    template<typename T>
    using VfsResult = std::expected<T, VfsError>;

    /** @brief Discriminates files from directories inside a @ref VfsEntry. */
    enum class EVfsEntryKind
    {
        File,
        Directory
    };

    /**
     * @brief A single item returned by @ref Vfs::List.
     *
     * @p name is the bare entry name (no leading path item).
     * @p size is meaningful only when @p kind == EVfsEntryKind::VfsFile;
     *         for directories it is always 0.
     */
    struct VfsEntry
    {
        std::string   name;
        EVfsEntryKind kind;
        std::size_t   size = 0;
    };

    /**
     * @brief Low-level file descriptor filled in by a @ref VfsProviderDesc.
     *
     * Providers construct one of these inside their `open` callback.
     * End users never interact with VfsFileDesc directly, they receive a @ref VfsFile handle.
     *
     * All callbacks must be set. Ownership of any underlying resource is managed
     * by capturing it in the lambdas (ie. via shared_ptr).
     *
     * @par Callback contracts
     * - @p read   - copy up to @p count bytes into @p dst; return bytes actually read.
     * - @p seek   - reposition the read cursor; @p offset is relative to the start of the file.
     * - @p tell   - return the current cursor position.
     * - @p size   - return total file size in bytes.
     * - @p eof    - return true if the cursor is at or past end-of-file.
     */
    struct VfsFileDesc
    {
        std::function<std::size_t(void* dst, std::size_t count)> read;
        std::function<void(std::size_t offset)>                  seek;
        std::function<std::size_t()>                             tell;
        std::function<std::size_t()>                             size;
        std::function<bool()>                                    eof;
    };

    /**
     * @brief Descriptor struct that defines a custom VFS provider.
     *
     * This is the primary extensibility point. Fill in the callbacks to teach the
     * VFS how to open, stat, and enumerate files from your backing store (zip, network,
     * memory, etc.). State is captured naturally via lambda closures - no inheritance needed.
     *
     * @par Example (in-memory provider)
     * @code
     *   std::unordered_map<std::string, std::vector<std::byte>> blob_store = { ... };
     *
     *   ts::VfsProviderDesc desc {
     *       .exists = [&](std::string_view p) { return blob_store.contains(std::string(p)); },
     *       .open   = [&](std::string_view p) -> ts::VfsResult<ts::VfsFileDesc> {
     *           auto it = blob_store.find(std::string(p));
     *           if (it == blob_store.end())
     *               return std::unexpected(ts::VfsError{ ts::EVfsErrorCode::NotFound, "not in blob store" });
     *           auto  pos  = std::make_shared<std::size_t>(0);
     *           auto& data = it->second;
     *           return ts::VfsFileDesc {
     *               .read = [&data, pos](void* dst, std::size_t n) {
     *                   n = std::min(n, data.size() - *pos);
     *                   std::memcpy(dst, data.data() + *pos, n);
     *                   *pos += n; return n;
     *               },
     *               .seek = [&data, pos](std::size_t off)  { *pos = std::min(off, data.size()); },
     *               .tell = [pos]()                         { return *pos; },
     *               .size = [&data]()                       { return data.size(); },
     *               .eof  = [&data, pos]()                  { return *pos >= data.size(); },
     *           };
     *       },
     *       .list = [&](std::string_view) -> ts::VfsResult<std::vector<ts::VfsEntry>> {
     *           // flat store: treat root as the only directory
     *           std::vector<ts::VfsEntry> out;
     *           for (auto& [k, v] : blob_store)
     *               out.push_back({ k, ts::EVfsEntryKind::VfsFile, v.size() });
     *           return out;
     *       },
     *   };
     * @endcode
     *
     * @note The @p list callback receives a path *relative to the provider's own root*,
     *       not the absolute VFS path. The VFS strips the mount prefix before dispatching.
     */
    struct VfsProviderDesc
    {
        /**
         * @brief Returns true if @p path exists within this provider (file or directory).
         * Path is relative to the provider root.
         */
        std::function<bool(std::string_view path)> exists;

        /**
         * @brief Attempts to open @p path for reading.
         * Path is relative to the provider root.
         * @return A @ref VfsFileDesc on success, or an @ref VfsError on failure.
         */
        std::function<VfsResult<VfsFileDesc>(std::string_view path)> open;

        /**
         * @brief Lists the immediate children of @p directory.
         * Path is relative to the provider root. Pass an empty string for the provider root itself.
         * @return A vector of @ref VfsEntry values, or an @ref VfsError.
         */
        std::function<VfsResult<std::vector<VfsEntry>>(std::string_view directory)> list;
    };

    /**
     * @brief A readable, seekable handle to an open file.
     *
     * Constructed internally by @ref Vfs::Open. Not copyable; movable.
     * The underlying resource is released when the VfsFile is destroyed.
     *
     * All methods are thread-compatible: concurrent access to distinct VfsFile
     * instances is safe; concurrent access to the *same* VfsFile instance is not.
     */
    class VfsFile
    {
        VfsFileDesc m_desc;

    public:
        explicit VfsFile(VfsFileDesc desc);

        VfsFile(const VfsFile&) = delete;
        VfsFile& operator=(const VfsFile&) = delete;
        VfsFile(VfsFile&&) = default;
        VfsFile& operator=(VfsFile&&) = default;

        /**
         * @brief Reads up to @p count bytes into @p dst.
         * @return Number of bytes actually read (may be less at end-of-file).
         */
        std::size_t Read(void* dst, std::size_t count);

        /**
         * @brief Repositions the read cursor to @p offset bytes from the start.
         */
        void Seek(std::size_t offset);

        /** @brief Returns the current cursor position. */
        [[nodiscard]] std::size_t Tell() const;

        /** @brief Returns the total size of the file in bytes. */
        [[nodiscard]] std::size_t Size() const;

        /** @brief Returns true if the cursor is at or past end-of-file. */
        [[nodiscard]] bool Eof() const;

        /**
         * @brief Reads the entire file into a byte buffer.
         *
         * Seeks to the beginning before reading.
         * @return Owned byte vector, or an @ref VfsError on failure.
         */
        VfsResult<std::vector<std::byte>> ReadBytes();

        /**
         * @brief Reads the entire file as a UTF-8 string.
         *
         * Seeks to the beginning before reading.
         * @return Owned string, or an @ref VfsError on failure.
         */
        VfsResult<std::string> ReadText();
    };

    /**
     * @brief Virtual filesystem with explicit mount points.
     *
     * On construction, a disk provider is automatically mounted at @p "/" rooted at
     * the current working directory. Additional providers can be mounted on top of
     * distinct path prefixes.
     *
     * Path rules:
     * - All paths are absolute and use @p '/' as separator.
     * - Trailing slashes are ignored.
     * - The VFS strips the matching mount prefix before handing the relative path to the provider.
     *
     * Mount conflict rules (enforced by @ref Mount):
     * - The requested mount name must not collide with an existing mount point.
     * - The requested mount name must not collide with a real entry (file or directory)
     *   visible through the @p "/" disk provider.
     *
     * Thread safety:
     * - @ref Mount is serialized by an internal mutex.
     * - @ref Open and @ref List acquire a mutex; concurrent reads are serialized, and so they're safe.
     */
    class Vfs
    {
        struct MountPoint;

        std::vector<MountPoint> m_mounts;
        mutable std::mutex      m_mutex;

        [[nodiscard]] std::string       m_StripPrefix(std::string_view mountPath, std::string_view fullPath) const;
        [[nodiscard]] const MountPoint* m_Resolve(std::string_view path) const;

    public:
        /**
         * @brief Constructs the VFS and registers the default disk provider at "/".
         *
         * The disk provider resolves paths relative to the process working directory
         * at the time of construction.
         */
        Vfs();

        ~Vfs() = default;

        Vfs(const Vfs&) = delete;
        Vfs& operator=(const Vfs&) = delete;

        /**
         * @brief Mounts a provider at the given absolute path prefix.
         *
         * @param mountPath  Absolute VFS path (ie. @p "/assets"). Must start with '/'.
         *                   Must not be "/" (the root is reserved for the disk provider).
         * @param provider   Descriptor describing the provider's behavior.
         *
         * @return `std::expected<void, VfsError>` - holds an @ref VfsError with code:
         *   - @p MountConflict if a mount already exists at @p mountPath.
         *   - @p MountConflict if a real entry (file or directory) visible through "/"
         *     already exists at the same name as the mount's top-level item.
         */
        VfsResult<void> Mount(std::string_view mountPath, VfsProviderDesc provider);

        /**
         * @brief Removes the provider mounted at @p mountPath.
         *
         * @return @ref VfsError with code @p NotFound if no mount exists at that path.
         */
        VfsResult<void> Unmount(std::string_view mountPath);

        /**
         * @brief Opens a file for reading.
         *
         * The VFS resolves @p path to the longest matching mount prefix, strips the
         * prefix, then delegates to the provider's @p open callback.
         *
         * @return A @ref VfsFile on success, or an @ref VfsError describing the failure.
         */
        VfsResult<VfsFile> Open(std::string_view path) const;

        /**
         * @brief Lists the immediate children of @p directory.
         *
         * When @p directory spans the boundary between two mount points (ie. listing "/"
         * when sub-mounts exist), the results from the disk provider and all matching
         * mounts are merged. Entries from sub-mounts shadow disk entries of the same name.
         *
         * @return A vector of @ref VfsEntry values, or an @ref VfsError.
         */
        VfsResult<std::vector<VfsEntry>> List(std::string_view directory) const;

        /**
         * @brief Returns true if @p path exists (as either a file or a directory).
         */
        [[nodiscard]] bool Exists(std::string_view path) const;
    };

}

#endif /* TS_VFS_H */

#if defined(TS_VFS_IMPLEMENTATION) && !defined(TS_VFS_BODY_IMPLEMENTED)
#define TS_VFS_BODY_IMPLEMENTED

#include <algorithm>
#include <cassert>
#include <filesystem>
#include <format>
#include <fstream>
#include <system_error>

namespace ts
{
    namespace
    {
        std::string NormalizePath(std::string_view path)
        {
            std::string out;
            out.reserve(path.size());
            bool lastSlash = false;
            for (char c : path)
            {
                if (c == '/')
                {
                    if (!lastSlash) out += c;
                    lastSlash = true;
                }
                else
                {
                    out += c;
                    lastSlash = false;
                }
            }

            if (out.size() > 1 && out.back() == '/')
                out.pop_back();
            return out;
        }

        std::string_view TopComponent(std::string_view path)
        {
            auto start = path.find_first_not_of('/');
            if (start == std::string_view::npos) return {};
            auto end = path.find('/', start);
            return path.substr(start, end == std::string_view::npos ? std::string_view::npos : end - start);
        }

        VfsError OsError(EVfsErrorCode code, const std::filesystem::path& p, const std::error_code& ec)
        {
            return { code, p.string() + ": " + ec.message() };
        }

        VfsProviderDesc MakeDiskProvider(std::filesystem::path root)
        {
            return VfsProviderDesc
            {
                .exists = [root](std::string_view relPath) {
                    std::error_code ec;
                    return std::filesystem::exists(root / relPath, ec);
                },

                .open = [root](std::string_view relPath) -> VfsResult<VfsFileDesc>
                {
                    std::filesystem::path full = root / relPath;
                    std::error_code ec;

                    if (!std::filesystem::exists(full, ec))
                        return std::unexpected(VfsError {
                            EVfsErrorCode::NotFound,
                            std::format("{}: not found", full.string())
                        });

                    if (std::filesystem::is_directory(full, ec))
                        return std::unexpected(VfsError {
                            EVfsErrorCode::NotAFile,
                            std::format("{}: not a file", full.string())
                        });

                    auto stream = std::make_shared<std::ifstream>(full, std::ios::binary);
                    if (!stream->is_open())
                        return std::unexpected(VfsError {
                            EVfsErrorCode::PermissionDenied,
                            std::format("{}: could not open", full.string())
                        });

                    stream->seekg(0, std::ios::end);
                    const std::size_t fileSize = static_cast<std::size_t>(stream->tellg());
                    stream->seekg(0, std::ios::beg);

                    return VfsFileDesc
                    {
                        .read = [stream](void* dst, std::size_t count) {
                            stream->read(static_cast<char*>(dst), static_cast<std::streamsize>(count));
                            return static_cast<std::size_t>(stream->gcount());
                        },
                        .seek = [stream](std::size_t offset) {
                            stream->clear();
                            stream->seekg(static_cast<std::streamoff>(offset), std::ios::beg);
                        },
                        .tell = [stream]() {
                            return static_cast<std::size_t>(stream->tellg());
                        },
                        .size = [fileSize]() {
                            return fileSize;
                        },
                        .eof = [stream]() {
                            return stream->eof();
                        }
                    };
                },

                .list = [root](std::string_view relPath) -> VfsResult<std::vector<VfsEntry>>
                {
                    std::filesystem::path dir = relPath.empty() ? root : root / relPath;
                    std::error_code ec;

                    if (!std::filesystem::exists(dir, ec))
                        return std::unexpected(VfsError {
                            EVfsErrorCode::NotFound,
                            std::format("{}: not found", dir.string())
                        });

                    if (!std::filesystem::is_directory(dir, ec))
                        return std::unexpected(VfsError {
                            EVfsErrorCode::NotADirectory,
                            std::format("{}: not a directory", dir.string())
                        });

                    std::vector<VfsEntry> entries;
                    for (const auto& dirent : std::filesystem::directory_iterator(dir, ec))
                    {
                        if (ec)
                            break;

                        VfsEntry entry;
                        entry.name = dirent.path().filename().string();

                        if (dirent.is_directory(ec))
                        {
                            entry.kind = EVfsEntryKind::Directory;
                            entry.size = 0;
                        }
                        else
                        {
                            entry.kind = EVfsEntryKind::File;
                            entry.size = static_cast<std::size_t>(dirent.file_size(ec));
                            if (ec)
                                entry.size = 0; // Non-fatal; size unknown.
                        }

                        entries.push_back(std::move(entry));
                    }

                    if (ec)
                        return std::unexpected(OsError(EVfsErrorCode::ProviderError, dir, ec));

                    return entries;
                },
            };
        }
    }

    // -----------------------------------------------------------------------------

    VfsFile::VfsFile(VfsFileDesc desc)
        : m_desc(std::move(desc))
    {
        assert(m_desc.read && "VfsFileDesc::read must not be null");
        assert(m_desc.seek && "VfsFileDesc::seek must not be null");
        assert(m_desc.tell && "VfsFileDesc::tell must not be null");
        assert(m_desc.size && "VfsFileDesc::size must not be null");
        assert(m_desc.eof  && "VfsFileDesc::eof  must not be null");
    }

    std::size_t VfsFile::Read(void* dst, std::size_t count)
    {
        return m_desc.read(dst, count);
    }

    void VfsFile::Seek(std::size_t offset)
    {
        m_desc.seek(offset);
    }

    std::size_t VfsFile::Tell() const
    {
        return m_desc.tell();
    }

    std::size_t VfsFile::Size() const
    {
        return m_desc.size();
    }

    bool VfsFile::Eof() const
    {
        return m_desc.eof();
    }

    VfsResult<std::vector<std::byte>> VfsFile::ReadBytes()
    {
        const std::size_t fileSize = m_desc.size();
        m_desc.seek(0);

        std::vector<std::byte> buf(fileSize);
        std::size_t totalRead = 0;

        while (totalRead < fileSize && !m_desc.eof())
        {
            std::size_t n = m_desc.read(reinterpret_cast<char*>(buf.data()) + totalRead, fileSize - totalRead);
            if (n == 0)
                break; // Provider signaled stall; avoid spinning.
            totalRead += n;
        }

        if (totalRead != fileSize)
            return std::unexpected(VfsError {
                EVfsErrorCode::ProviderError,
                std::format("ReadBytes: expected {} bytes, got {}", fileSize, totalRead)
            });

        return buf;
    }

    VfsResult<std::string> VfsFile::ReadText()
    {
        return ReadBytes().transform([](std::vector<std::byte>&& bytes) {
            return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        });
    }

    // -----------------------------------------------------------------------------

    struct Vfs::MountPoint
    {
        std::string     path;
        VfsProviderDesc provider;
    };

    std::string Vfs::m_StripPrefix(std::string_view mountPath, std::string_view fullPath) const
    {
        if (mountPath == "/")
        {
            if (fullPath.size() <= 1) return {};
            return std::string(fullPath.substr(1));
        }

        if (fullPath.size() <= mountPath.size())
            return {};

        return std::string(fullPath.substr(mountPath.size() + 1));
    }

    const Vfs::MountPoint* Vfs::m_Resolve(std::string_view path) const
    {
        for (const auto& mp : m_mounts)
        {
            if (mp.path == "/")
                return &mp;

            if (path.starts_with(mp.path))
                if (path.size() == mp.path.size() || path[mp.path.size()] == '/')
                    return &mp;
        }

        return nullptr;
    }

    // -----------------------------------------------------------------------------

    Vfs::Vfs()
    {
        m_mounts.push_back(MountPoint {
            .path = "/",
            .provider = MakeDiskProvider(std::filesystem::current_path()),
        });
    }

    VfsResult<void> Vfs::Mount(std::string_view mountPath, VfsProviderDesc provider)
    {
        const std::string normalized = NormalizePath(mountPath);

        if (normalized == "/")
            return std::unexpected(VfsError {
                EVfsErrorCode::MountConflict,
                "Cannot mount over the root provider"
            });

        if (!normalized.starts_with('/'))
            return std::unexpected(VfsError {
                EVfsErrorCode::MountConflict,
                std::format("Mount path must be absolute (start with '/'): {}", normalized)
            });

        std::scoped_lock<std::mutex> lock(m_mutex);

        for (const auto& mp : m_mounts)
        {
            if (mp.path == normalized)
                return std::unexpected(VfsError {
                    EVfsErrorCode::MountConflict,
                    std::format("A provider is already mounted at: {}", normalized)
                });
        }

        const std::string_view top = TopComponent(normalized);
        const MountPoint* root = m_Resolve("/");
        if (root && root->provider.exists(top))
            return std::unexpected(VfsError {
                EVfsErrorCode::MountConflict,
                std::format("A filesystem entry already exists at: /{}", std::string(top))
            });

        auto it = std::ranges::find_if(m_mounts, [&](const MountPoint& mp) {
            return mp.path.size() < normalized.size();
        });

        m_mounts.insert(it, MountPoint {
            .path = normalized,
            .provider = std::move(provider)
        });

        return {};
    }

    VfsResult<void> Vfs::Unmount(std::string_view mountPath)
    {
        const std::string normalized = NormalizePath(mountPath);

        if (normalized == "/")
            return std::unexpected(VfsError {
                EVfsErrorCode::MountConflict,
                "Cannot unmount the root provider"
            });

        std::scoped_lock<std::mutex> lock(m_mutex);

        auto it = std::ranges::find_if(m_mounts, [&](const MountPoint& mp) {
            return mp.path == normalized;
        });

        if (it == m_mounts.end())
            return std::unexpected(VfsError {
                EVfsErrorCode::NotFound,
                std::format("No provider mounted at: {}", normalized)
            });

        m_mounts.erase(it);
        return {};
    }

    VfsResult<VfsFile> Vfs::Open(std::string_view path) const
    {
        const std::string normalized = NormalizePath(path);

        std::scoped_lock<std::mutex> lock(m_mutex);

        const MountPoint* mp = m_Resolve(normalized);
        if (!mp)
            return std::unexpected(VfsError {
                EVfsErrorCode::NotFound,
                std::format("No provider for: {}", normalized)
            });

        const std::string relative = m_StripPrefix(mp->path, normalized);

        return mp->provider.open(relative).transform([&path](VfsFileDesc&& desc) {
            std::println("ts_vfs: Opening: {}", path);
            return VfsFile(std::move(desc));
        });
    }

    VfsResult<std::vector<VfsEntry>> Vfs::List(std::string_view directory) const
    {
        const std::string normalized = NormalizePath(directory);

        std::scoped_lock<std::mutex> lock(m_mutex);

        // Find the primary provider for this path.
        const MountPoint* primary = m_Resolve(normalized);
        if (!primary)
            return std::unexpected(VfsError {
                EVfsErrorCode::NotFound,
                std::format("No provider for: {}", normalized)
            });

        const std::string relative = m_StripPrefix(primary->path, normalized);
        auto result = primary->provider.list(relative);
        if (!result)
            return result;

        std::vector<VfsEntry>& entries = *result;

        for (const auto& mp : m_mounts)
        {
            if (mp.path == "/" || mp.path == normalized)
                continue;

            const std::string_view prefix = (normalized == "/")
                ? std::string_view("/")
                : std::string_view(normalized);

            if (!mp.path.starts_with(prefix))
                continue;

            const std::size_t restStart = (normalized == "/") ? 1 : normalized.size() + 1;
            if (restStart > mp.path.size())
                continue;

            const std::string_view rest = std::string_view(mp.path).substr(restStart);
            if (rest.empty() || rest.find('/') != std::string_view::npos)
                continue;

            std::erase_if(entries, [&](const VfsEntry& e) { return e.name == rest; });

            entries.push_back(VfsEntry {
                .name = std::string(rest),
                .kind = EVfsEntryKind::Directory,
                .size = 0,
            });
        }

        return result;
    }

    bool Vfs::Exists(std::string_view path) const
    {
        const std::string normalized = NormalizePath(path);

        std::scoped_lock<std::mutex> lock(m_mutex);

        const MountPoint* mp = m_Resolve(normalized);
        if (!mp)
            return false;

        // A path that exactly matches a mount point always exists as a directory
        if (mp->path == normalized && normalized != "/")
            return true;

        const std::string relative = m_StripPrefix(mp->path, normalized);
        return mp->provider.exists(relative);
    }

}

#endif /* TS_VFS_IMPLEMENTATION */
