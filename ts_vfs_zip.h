/**
 * @file ts_vfs_zip.h
 * @brief Zip archive provider for ts_vfs. Requires miniz (single-header, public domain).
 *
 * @author Charles 'xtrium' Riffaud-Declercq
 * @license CC BY-SA 4.0 - https://creativecommons.org/licenses/by-sa/4.0/
 *
 * Usage:
 *   Include miniz.h (or miniz.c with MINIZ_HEADER_FILE_ONLY) before this header.
 *   Define TS_VFS_ZIP_IMPLEMENTATION in exactly one translation unit before including.
 *
 * Example:
 * @code
 *   #define TS_VFS_IMPLEMENTATION
 *   #include "ts_vfs.h"
 *
 *   #include "miniz.h"
 *   #define TS_VFS_ZIP_IMPLEMENTATION
 *   #include "ts_vfs_zip.h"
 *
 *   ts::Vfs vfs;
 *
 *   std::ignore = ts::MakeZipProvider("archive.zip")
 *       .and_then([&vfs](ts::VfsProviderDesc desc) { return vfs->Mount("/mountpoint", std::move(desc)); });
 * @endcode
 */

#ifndef TS_VFS_ZIP_H
#define TS_VFS_ZIP_H

#include "ts_vfs.h"

#include <string>

namespace ts
{
    VfsResult<VfsProviderDesc> MakeZipProvider(const std::string& zipPath);
}
#endif /* TS_VFS_ZIP_H */


#ifdef TS_VFS_ZIP_IMPLEMENTATION

#include <algorithm>
#include <cassert>
#include <cstring>
#include <format>
#include <memory>
#include <mutex>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifndef MINIZ_HEADER_INCLUDED
# define MINIZ_IMPL
# include "miniminiz.h"
#endif /* MINIZ_HEADER_INCLUDED */

namespace ts
{
    namespace detail
    {
        struct ZipArchive
        {
            mz_zip_archive zip   = {};
            std::mutex     mutex = {};

            std::unordered_map<std::string, mz_uint> fileIndex;
            std::unordered_set<std::string>          dirs;

            ~ZipArchive()
            {
                mz_zip_reader_end(&zip);
            }

            ZipArchive() = default;
            ZipArchive(const ZipArchive&) = delete;
            ZipArchive& operator=(const ZipArchive&) = delete;
        };

        std::string_view StripLeadingSlash(std::string_view path)
        {
            if (!path.empty() && path.front() == '/')
                return path.substr(1);
            return path;
        }

        std::string StripTrailingSlash(std::string_view path)
        {
            std::string s(path);
            if (!s.empty() && s.back() == '/')
                s.pop_back();
            return s;
        }

        void IndexDirectories(ZipArchive& archive, std::string_view filePath)
        {
            std::string_view remaining = filePath;
            while (true)
            {
                auto slash = remaining.rfind('/');
                if (slash == std::string_view::npos)
                    break;
                remaining = remaining.substr(0, slash);
                archive.dirs.emplace(remaining);
            }
        }

        std::shared_ptr<ZipArchive> OpenAndIndex(const std::string& zipPath, VfsError& outError)
        {
            auto archive = std::make_shared<ZipArchive>();

            if (!mz_zip_reader_init_file(&archive->zip, zipPath.c_str(), 0))
            {
                outError = VfsError {
                    EVfsErrorCode::NotFound,
                    std::format("{}: could not open zip ({})",
                        zipPath,
                        mz_zip_get_error_string(mz_zip_get_last_error(&archive->zip))
                    )
                };
                return nullptr;
            }

            const mz_uint count = mz_zip_reader_get_num_files(&archive->zip);
            for (mz_uint i = 0; i < count; ++i)
            {
                mz_zip_archive_file_stat stat;
                if (!mz_zip_reader_file_stat(&archive->zip, i, &stat))
                    continue;

                std::string name = StripTrailingSlash(stat.m_filename);

                if (mz_zip_reader_is_file_a_directory(&archive->zip, i))
                    archive->dirs.emplace(name);
                else
                {
                    archive->fileIndex.emplace(name, i);
                    IndexDirectories(*archive, name);
                }
            }

            return archive;
        }

        VfsResult<VfsFileDesc> OpenEntry(const std::shared_ptr<ZipArchive>& archive, const std::string& entryPath, mz_uint index)
        {
            std::size_t uncompressedSize = 0;
            void*       raw              = nullptr;
            
            {
                std::scoped_lock lock(archive->mutex);
                raw = mz_zip_reader_extract_to_heap(&archive->zip, index, &uncompressedSize, 0);
            }

            if (!raw)
                return std::unexpected(VfsError {
                    EVfsErrorCode::ProviderError,
                    std::format("{}: decompression failed ({})",
                        entryPath,
                        mz_zip_get_error_string(mz_zip_get_last_error(&archive->zip))
                    )
                });

            // Transfer ownership from miniz's malloc into a vector so we get RAII.
            auto buf = std::make_shared<std::vector<std::byte>>(uncompressedSize);
            std::memcpy(buf->data(), raw, uncompressedSize);
            mz_free(raw);

            const std::size_t fileSize = buf->size();
            auto pos = std::make_shared<std::size_t>(0);

            return VfsFileDesc {
                .read = [buf, pos](void* dst, std::size_t count) {
                    count = std::min(count, buf->size() - *pos);
                    std::memcpy(dst, buf->data() + *pos, count);
                    *pos += count;
                    return count;
                },
                .seek = [buf, pos](std::size_t offset) {
                    *pos = std::min(offset, buf->size());
                },
                .tell = [pos]() {
                    return *pos;
                },
                .size = [fileSize]() {
                    return fileSize;
                },
                .eof = [buf, pos]() {
                    return *pos >= buf->size();
                }
            };
        }
    }

    VfsResult<VfsProviderDesc> MakeZipProvider(const std::string& zipPath)
    {
        VfsError openError;
        auto archive = detail::OpenAndIndex(zipPath, openError);
        if (!archive)
            return std::unexpected(std::move(openError));

        return VfsProviderDesc
        {
            .exists = [archive](std::string_view path) {
                const std::string key(detail::StripLeadingSlash(path));
                return archive->fileIndex.contains(key) || archive->dirs.contains(key);
            },
            .open = [archive](std::string_view path) -> VfsResult<VfsFileDesc> {
                const std::string key(detail::StripLeadingSlash(path));

                if (archive->dirs.contains(key))
                    return std::unexpected(VfsError {
                        EVfsErrorCode::NotAFile,
                        std::format("{}: is a directory", key)
                    });

                auto it = archive->fileIndex.find(key);
                if (it == archive->fileIndex.end())
                    return std::unexpected(VfsError {
                        EVfsErrorCode::NotFound,
                        std::format("{}: not found in archive", key)
                    });

                return OpenEntry(archive, key, it->second);
            },
            .list = [archive](std::string_view directory) -> VfsResult<std::vector<VfsEntry>>
            {
                const std::string prefix(detail::StripLeadingSlash(detail::StripTrailingSlash(directory)));

                if (!prefix.empty() && !archive->dirs.contains(prefix))
                    return std::unexpected(VfsError {
                        EVfsErrorCode::NotADirectory,
                        std::format("{}: not a directory in archive", prefix)
                    });

                std::vector<VfsEntry> entries;

                auto immediateChild = [&](std::string_view candidate) -> std::optional<std::string_view>
                {
                    if (!prefix.empty())
                    {
                        if (!candidate.starts_with(prefix))        return std::nullopt;
                        if (candidate.size() <= prefix.size() + 1) return std::nullopt;
                        if (candidate[prefix.size()] != '/')       return std::nullopt;
                        candidate = candidate.substr(prefix.size() + 1);
                    }

                    if (candidate.find('/') != std::string_view::npos)
                        return std::nullopt;

                    if (candidate.empty())
                        return std::nullopt;

                    return candidate;
                };

                for (const auto& [path, index] : archive->fileIndex)
                {
                    auto child = immediateChild(path);
                    if (!child)
                        continue;

                    mz_zip_archive_file_stat stat;
                    std::size_t size = 0;
                    {
                        std::scoped_lock lock(archive->mutex);
                        if (mz_zip_reader_file_stat(&archive->zip, index, &stat))
                            size = static_cast<std::size_t>(stat.m_uncomp_size);
                    }

                    entries.push_back(VfsEntry {
                        .name = std::string(*child),
                        .kind = EVfsEntryKind::File,
                        .size = size,
                    });
                }

                for (const auto& dir : archive->dirs)
                {
                    auto child = immediateChild(dir);
                    if (!child)
                        continue;

                    entries.push_back(VfsEntry {
                        .name = std::string(*child),
                        .kind = EVfsEntryKind::Directory,
                        .size = 0,
                    });
                }

                return entries;
            },
        };
    }
}

#endif /* TS_VFS_ZIP_IMPLEMENTATION */