#pragma once

/**
 * ============================================================================
 * FSController Class - A C++ File System Utility Module
 * ============================================================================
 *
 * DISCLAIMER OF WARRANTY:
 *
 * This software is provided 'as-is', without any express or implied warranty.
 * In no event will the author(s) be held liable for any damages arising from
 * the use of this software, including but not limited to:
 *
 * - Loss of data
 * - Any other type of loss or damage
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would
 *    be appreciated but is not required.
 *
 * 2. Altered source versions must be plainly marked as such, and must not
 *    be misrepresented as being the original software.
 *
 * 3. This notice may not be removed or altered from any source distribution.
 *
 * LIMITATION OF LIABILITY:
 *
 * In no event will the author(s) be liable for any damages, including but
 * not limited to incidental, consequential, or punitive damages, arising
 * out of the use of this software.
 *
 * COPYING AND DISTRIBUTION:
 *
 * This software may be copied and distributed free of charge, provided
 * that the above copyright notice, disclaimer, and limitations of liability
 * are included in all copies.
 *
 * AUTHORIZATION:
 *
 * By using this software, you acknowledge that you have read and understood
 * the terms and conditions of this license, and agree to be bound by them.
 *
 * TRADEMARKS:
 *
 * The names of actual companies and products mentioned in this software
 * may be the trademarks of their respective owners.
 *
 * ACKNOWLEDGMENT:
 *
 * The authors would like to acknowledge the contributions of the C++
 * community, and the many individuals who have helped shape the C++
 * standard library.
 *
 * ============================================================================
 *
 * Written by [Somorpher], [2024].
 */

/**
 *
 * +++++++++++++++++++++++++++++++++++++++++++++++++++++++-------------
 *
 *
 * This C++ code implements a comprehensive file system utility module that provides a wide
 * range of operations for managing files and directories. At the heart of the code is the
 * FSController class, a template-based class that allows for flexibility in choosing the
 * type of foreign key used to identify file profiler structures.
 * The FSController class provides a wide range of functions for interacting with the file system,
 * including reading and writing files using memory mapping. The FileRead function uses the mmap
 * system call to map a file into memory, allowing for efficient and fast access to file contents.
 * The FileWrite function, on the other hand, uses the mmap system call to map a file into memory,
 * and then uses the memcpy function to copy data from a buffer into the mapped memory region.
 * In addition to reading and writing files, the FSController class also provides functions for
 * creating and deleting files, checking if a file exists, is a text file, executable, or a symlink,
 * and creating and deleting directories. These functions are implemented using the std::filesystem
 * library, which provides a modern and efficient way to interact with the file system.
 * The FSController class also provides functions for recursively aggregating directory entries,
 * scanning directories for specific file types, and creating backups of directories. These
 * functions are  implemented using the std::filesystem::directory_iterator class, which provides a
 * way to iterate over the entries in a directory. Another key feature of the FSController class is
 * its ability to create, register, and manage file profiler structures. A file profiler structure
 * is a data structure that contains information about a file, such as its name, size, and contents.
 * The FSController class provides functions for creating and registering these structures, as well
 * as for performing garbage collection to ensure that unused profiler structures are properly
 * cleaned up. The FSController class is designed to be thread-safe, with a mutex used to protect
 * access to shared resources. This ensures that the class can be safely used in multi-threaded
 * environments without fear of data corruption or other concurrency-related issues. One notable
 * feature of the FSController class is its use of attribute macros to specify compiler
 * optimizations and other attributes for its member functions. For example, the __0x_attr_gri macro
 * is used to specify that a function should be optimized for performance, while the
 * __0x_attr_psrsgp macro is used to specify that a function should be optimized for size. The
 * FSController class also provides a number of convenience functions for working with files and
 * directories. For example, the CreateFile function creates a new file with the specified name and
 * contents, while the DeleteFile function deletes a file with the specified name. The
 * CreateDirectory function creates a new directory with the specified name, while the
 * DeleteDirectory function deletes a directory with the specified name.
 *
 * +++++++++++++++++++++++++++++++++++++++++++++++++++++++-------------
 *
 */

/*                     Headers/Libs                      *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

#include <algorithm>
#include <array>
#include <deque>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <random>
#include <stack>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <thread>
#include <type_traits>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <functional>
#include <vector>

/**
 * Namespace Pollution Guard, naming-collision prevention
 *
 */
#ifndef __MODULE_FS_CONTROLLER__
#define __MODULE_FS_CONTROLLER__

/*                     Namespace                         *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
namespace FSControllerModule
{

#define IS_DEBUGGING_CODE 1 // remove this definition for production

/**
 * Os/Architecture Detection
 *
 */
#if defined(__linux__) || defined(__APPLE__)

/*                      Global Macro                     *\
\*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
#ifdef __GNUC__
#define __SUPPORTED_COMPILER_1__ __GNUC__
#endif

#ifdef __clang__
#define __SUPPORTED_COMPILER_2__ __clang__
#endif

#ifdef IS_DEBUGGING_CODE
#define ATTR_OPTIMIZE_LEVEL "0"
#else
#define ATTR_OPTIMIZE_LEVEL "3"
#endif

#define FS_MAX_FILE_NAME_LENGTH (std::uint16_t)200         /* the max length for individual absolute address */
#define FS_MAX_COLLECTION_STACK_SIZE (std::uint32_t)100000 /* max value for instance aggregation size */

/* FKType is the foreign key type name to use for entity associations */
#define __tm_file_aggregation template <typename _FKType, typename = std::enable_if<!std::is_array_v<_FKType> && !std::is_pointer_v<_FKType>>>

/**
 * Compiler Detection, only implement attributes with supported compiler installed
 */
#if defined(__SUPPORTED_COMPILER_1__) || defined(__SUPPORTED_COMPILER_2__)

#define __0x_attr_gri __attribute__((hot, no_icf, warn_unused_result, nothrow, pure, zero_call_used_regs("all"), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_psrsgp __attribute__((no_icf, warn_unused_result, nothrow, access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_psrscp __attribute__((no_icf, nothrow, always_inline, access(read_only, 1), zero_call_used_regs("all"), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_cc __attribute__((no_icf, nothrow, always_inline, cold, access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_mc __attribute__((no_icf, nothrow, always_inline, cold, access(read_write, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_co __attribute__((no_icf, nothrow, always_inline, const, cold, warn_unused_result, access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_fe __attribute__((no_icf, nothrow, always_inline, flatten, pure, hot, warn_unused_result, access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_itf __attribute__((no_icf, nothrow, always_inline, flatten, pure, warn_unused_result, no_stack_protector, access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_iex __attribute__((no_icf, nothrow, always_inline, flatten, pure, warn_unused_result, no_stack_protector, access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_isl __attribute__((no_icf, nothrow, always_inline, flatten, pure, warn_unused_result, no_stack_protector, access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_id __attribute__((no_icf, nothrow, always_inline, flatten, pure, warn_unused_result, no_stack_protector, access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_fr __attribute__((no_icf, warn_unused_result, hot, stack_protect, zero_call_used_regs("used"), access(read_only, 1), access(read_only, 2), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_fw __attribute__((no_icf, stack_protect, hot, zero_call_used_regs("used"), access(read_only, 1), access(read_only, 2), access(read_only, 3), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_rnp __attribute__((no_icf, nothrow, stack_protect, hot, zero_call_used_regs("used"), access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_gss \
    __attribute__((no_icf, nothrow, noipa, no_stack_protector, pure, flatten, warn_unused_result, no_sanitize_address, no_sanitize_coverage, no_sanitize_undefined, optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_gci \
    __attribute__((no_icf, nothrow, noipa, no_stack_protector, pure, flatten, warn_unused_result, no_sanitize_address, no_sanitize_coverage, no_sanitize_undefined, optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_gsp __attribute__((no_icf, nothrow, stack_protect, warn_unused_result, access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_ifc __attribute__((no_icf, nothrow, stack_protect, warn_unused_result, cold, flatten, access(read_write, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_cpm                                                                                                                                                                 \
    __attribute__((no_icf, nothrow, stack_protect, warn_unused_result, hot, flatten, pure, access(read_only, 1), access(read_only, 2), access(read_only, 3), zero_call_used_regs("used"), \
                   optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_ofd __attribute__((no_icf, stack_protect, warn_unused_result, hot, flatten, pure, access(read_only, 1), access(read_only, 2), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_cfs __attribute__((no_icf, warn_unused_result, flatten, pure, access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_vms __attribute__((no_icf, flatten, stack_protect, zero_call_used_regs("used"), access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_amb __attribute__((no_icf, nothrow, flatten, stack_protect, tainted_args, zero_call_used_regs("used"), access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_dmc __attribute__((no_icf, flatten, stack_protect, zero_call_used_regs("all"), access(read_write, 1), access(read_write, 2), access(read_only, 3), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_drz __attribute__((no_icf, flatten, stack_protect, always_inline, access(read_only, 1), access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_cps __attribute__((no_icf, flatten, nothrow, pure, warn_unused_result, no_stack_protector, noipa, access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_cmb __attribute__((no_icf, flatten, nothrow, stack_protect, zero_call_used_regs("used"), access(write_only, 1), access(read_only, 2), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_gsptr __attribute__((no_icf, cold, nothrow, always_inline, warn_unused_result, optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_dprf __attribute__((no_icf, nothrow, always_inline, access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_cfl __attribute__((no_icf, always_inline, access(read_only, 1), access(read_only, 2), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_cdir __attribute__((no_icf, always_inline, nothrow, access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_cdire __attribute__((no_icf, warn_unused_result, access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_dirprf __attribute__((no_icf, cold, warn_unused_result, access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_delfl __attribute__((no_icf, always_inline, no_stack_protector, access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_cdbk __attribute__((no_icf, cold, warn_unused_result, stack_protect, zero_call_used_regs("used"), access(read_only, 1), access(read_only, 2), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_dcft __attribute__((cold, warn_unused_result, access(read_only, 1), access(read_only, 2), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_dirwp __attribute__((cold, access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_fssh __attribute__((no_icf, always_inline, access(read_only, 1), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_recaggr __attribute__((hot, nothrow, access(read_only, 1), stack_protect, zero_call_used_regs("used"), optimize(ATTR_OPTIMIZE_LEVEL)))
#define __0x_attr_FSC_dirbkv __attribute__((no_icf, warn_unused_result, cold, access(read_only, 1), access(read_only, 2), optimize(ATTR_OPTIMIZE_LEVEL)))

#else

#define __0x_attr_gri [[nodiscard, nothrow]]
#define __0x_attr_psrsgp [[nodiscard, nothrow]]
#define __0x_attr_psrscp [[nothrow]]
#define __0x_attr_FSC_cc [[nothrow, nodiscard]]
#define __0x_attr_FSC_mc [[nothrow, nodiscard]]
#define __0x_attr_FSC_co [[nothrow, nodiscard]]
#define __0x_attr_FSC_fe [[nothrow, nodiscard]]
#define __0x_attr_FSC_itf [[nothrow, nodiscard]]
#define __0x_attr_FSC_iex [[nothrow, nodiscard]]
#define __0x_attr_FSC_isl [[nothrow, nodiscard]]
#define __0x_attr_FSC_id [[nothrow, nodiscard]]
#define __0x_attr_FSC_fr [[nodiscard]]
#define __0x_attr_FSC_fw [[nodiscard]]
#define __0x_attr_FSC_rnp [[nothrow]]
#define __0x_attr_FSC_gss [[nothrow, nodiscard]]
#define __0x_attr_FSC_gci [[nothrow, nodiscard]]
#define __0x_attr_FSC_gsp [[nothrow, nodiscard]]
#define __0x_attr_FSC_ifc [[nothrow, nodiscard]]
#define __0x_attr_FSC_cpm [[nothrow, nodiscard]]
#define __0x_attr_FSC_ofd [[nodiscard]]
#define __0x_attr_FSC_ofs [[nodiscard]]
#define __0x_attr_FSC_vms [[nothrow]]
#define __0x_attr_FSC_amb [[nothrow]]
#define __0x_attr_FSC_dmc [[nothrow]] // ?
#define __0x_attr_FSC_drz [[nothrow]] // ?
#define __0x_attr_FSC_cps [[nothrow, nodiscard]]
#define __0x_attr_FSC_cmb [[nothrow]]
#define __0x_attr_FSC_gsp [[nothrow]]
#define __0x_attr_FSC_dprf [[nothrow]]
#define __0x_attr_FSC_cfl [[]]
#define __0x_attr_FSC_cdir [[nothrow]]
#define __0x_attr_FSC_cdire [[]]
#define __0x_attr_FSC_dirprf [[]]
#define __0x_attr_FSC_delfl [[]]
#define __0x_attr_FSC_cdbk [[]]
#define __0x_attr_FSC_dcft [[]]
#define __0x_attr_FSC_dirwp [[]]
#define __0x_attr_FSC_fssh [[]]
#define __0x_attr_FSC_recaggr [[]]
#define __0x_attr_FSC_dirbkv [[]]

#endif

    /**
     * Debugging configuration mode, remove this macro for production use!
     */

#ifdef IS_DEBUGGING_CODE
#if !defined(__with_optimize_perform__)
#define __with_optimize_perform__ optimize("0") // 0 optimization for compiler
#endif
#else
#if !defined(__with_optimize_perform__)
#define __with_optimize_perform__ optimize("3") // 3 max optimization
#endif
#endif

    /**
     * Random Number Generator Static Function(Namespace Encapsulated)
     */
    __0x_attr_gri static const std::uint64_t GenerateRandomId(void) noexcept
    {
        std::random_device _d;
        std::mt19937 _eng(_d());
        std::uniform_int_distribution<uint64_t> _g(9999999999999, 9999999999999999);
        return _g(_eng);
    };

    /*                      Type Alias                       *\
    \*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
    using String_t = std::basic_string<char>;
    using StringView_t = std::basic_string_view<char>;
    typedef char *fMap_t;
    typedef String_t _FKType;
    typedef _FKType FKt;

    /*                      Enumeration                      *\
    \*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
    enum class eFileDescriptorMode : uint8_t
    {
        READ = 0,
        WRITE,
        READ_WRITE
    };

    /*                      Structure                        *\
    \*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

#pragma pack(1)
    struct alignas(void *) stFileDescriptor
    {
        String_t file_content{}; /* contains file content */
        String_t file_name{};    /* full path(absolute path) to file*/
        size_t file_size{};      /* file size in bytes */

        /* Clean struct file associated information */
        inline void Clean() noexcept
        {
            if (!file_content.empty())
                file_content.clear();

            if (!file_name.empty())
                file_name.clear();
        };

        ~stFileDescriptor() noexcept
        {
            Clean();
        };
    };

    /**
     *
     * file profile register structure, register file profiler structure block within "stack",
     * and profile stack register size within "reg_stack_size" member variables
     */
    struct alignas(void *) stProfilerStackRegister
    {
        std::unordered_map<_FKType, struct stFileDescriptor> stack_register{}; /* stack register, allocates file name(abs. address) as key and new file
                                                                                  descriptor instance. */
        size_t reg_stack_size{};                                               /* address register stack size */

        bool gc_executed{false};

        /**
         *
         * Helper Utility Function, locate and get fs description at index _i.
         * @param _FKType the index to search for
         * @returns struct stFileDescriptor, the descriptor at
         */
        __0x_attr_psrsgp inline const struct stFileDescriptor getProfile(const _FKType _profile_id) noexcept
        {
            if (reg_stack_size > 0) [[likely]]
            {
                if (stack_register.find(_profile_id) != stack_register.end())
                {
                    return stack_register[_profile_id];
                }
            }
            return {};
        };

        __0x_attr_psrscp inline void createProfile(const struct stFileDescriptor &_new_profile) noexcept
        {
            if (++reg_stack_size < FS_MAX_COLLECTION_STACK_SIZE - 1) [[likely]]
            {
                if (stack_register.find(_new_profile.file_name) == stack_register.end())
                {
                    stack_register.insert({_new_profile.file_name, std::move(_new_profile)});
                }
                return;
            }
            reg_stack_size--;
        };

        inline void eraseProfile(const _FKType _fk)
        {
            if (gc_executed)
                return;
            if (reg_stack_size > 0 && reg_stack_size-- > 0) [[likely]]
            {
                auto rsi = stack_register.find(_fk);
                if (rsi != stack_register.end()) [[likely]]
                {
                    stack_register.erase(rsi);
                }
            }
        };

        inline void GarbageCollect(void)
        {
            if (!gc_executed)
            {
                gc_executed = true;
                if (reg_stack_size > 0) [[likely]]
                {
                    for (auto &[fKey, profile_description] : stack_register)
                    {
                        eraseProfile(profile_description.file_name);
                    }
                }
            }
        };

        stProfilerStackRegister() = default;

        stProfilerStackRegister(const stProfilerStackRegister &o) = default;
        stProfilerStackRegister(stProfilerStackRegister &&o) = default;

        stProfilerStackRegister &operator=(const stProfilerStackRegister &o) = default;
        stProfilerStackRegister &operator=(stProfilerStackRegister &&o) = default;

        ~stProfilerStackRegister(void) noexcept
        {
            GarbageCollect();
        };
    };

#pragma pack()

    typedef struct alignas(void *)
    {
        std::vector<String_t> registry{};
        String_t largest_file_path{};
        std::size_t registry_size{0};
        std::size_t max_size{0};
        std::size_t min_size{0};
    } stDirectoryCollectionStat;

    typedef struct alignas(void *)
    {
        String_t path{};
        String_t file{};
        bool has_found{false};
    } stDirectoryLookup;

    /*             Template Specialization                   *\
    \*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
    template <typename _DirLookupType>
    struct is_dir_lookup_return_type : std::disjunction<std::is_same<_DirLookupType, stDirectoryLookup>, std::is_same<_DirLookupType, std::vector<stDirectoryLookup>>>
    {
    };

    template <typename _DirLookupType>
    inline constexpr bool is_dir_lookup_return_type_v = is_dir_lookup_return_type<_DirLookupType>::value;

    /*                          Class                        *\
    \*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

    /**
     * @class FSController
     * foreign key type referes to the FK used to allocate/register file descriptor/profilers. will be used to get/set new entries.
     */
    template <typename _ForeignKeyType_ = String_t>
    class FSController
    {
        using directoryScanResult_t = std::unordered_map<_ForeignKeyType_, struct stFileDescriptor>;

    private:

    bool sync_backup_exec_state;
        struct stProfilerStackRegister _profile_stack_reg; /* file profile stack register */

        std::uint64_t _fs_instance_uid = GenerateRandomId(); /* fs instance unique id, for copy/move semantics, avoid copy */

        bool _fs_new_instance = false; /* boolean flag indicating if instance is new or used,
                                          double-free error prevention */

        std::mutex _mtx_guard;

    public:
        /* FS Controller default Constructor */
        explicit FSController() noexcept
        {
            if (!this->_fs_new_instance)
                this->_fs_new_instance = true;
        };

        /* FS Controller Copy Constructor */
        __0x_attr_FSC_cc FSController(const FSController &_o) noexcept : _profile_stack_reg(_o._profile_stack_reg), _fs_instance_uid(_o._fs_instance_uid), _fs_new_instance(_o._fs_instance_uid) {};

        /* FS Controller Copy Operator Overload */
        __0x_attr_FSC_cc FSController &operator=(const FSController &_o) noexcept
        {
            return *this->__initFsController<const FSController &>(_o);
        };

        /* FS Controller Move Constructor */
        __0x_attr_FSC_mc FSController(FSController &&_o) noexcept
            : _profile_stack_reg(std::move(_o._profile_stack_reg)), _fs_instance_uid(std::move(_o._fs_instance_uid)), _fs_new_instance(std::move(_o._fs_instance_uid)) {};

        /* FS Controller Move Operator Overload */
        __0x_attr_FSC_mc FSController &operator=(FSController &&_o) noexcept
        {
            return *this->__initFsController<FSController &&>(std::move(_o));
        };

        /* FS Controller Comparision Operator Overload */
        __0x_attr_FSC_co constexpr bool operator==(const FSController &_o) noexcept
        {
            return this->_fs_instance_uid == _o._fs_instance_uid;
        };
        __0x_attr_FSC_co constexpr bool operator!=(const FSController &_o) noexcept
        {
            return !(this->_fs_instance_uid == _o._fs_instance_uid);
        };

        /**
         *
         * check if file_name exists or not.
         * @param StringView_t absolute path to target file
         * @returns bool true if file_name is found, false otherwise
         *
         */
        __0x_attr_FSC_fe inline static const bool FileExists(const StringView_t &file_name) noexcept
        {
            if (file_name.empty() || file_name.size() > FS_MAX_FILE_NAME_LENGTH || file_name.find(" ") != std::string::npos) [[unlikely]]
                return false;
            return std::filesystem::exists(file_name.data());
        };

        /**
         *
         * check if every file within file_list exists or not, will return failure if even 1
         * is missing.
         * @param std::unordered_set<String_t> list with target files
         * @returns bool true if every target within file_list is found, false otherwise
         *
         */
        __0x_attr_FSC_fe inline static const bool FileExists(const std::unordered_set<String_t> &file_list) noexcept
        {
            if (file_list.empty() && file_list.size() > 500000) [[unlikely]]
                return false;

            for (const String_t &file_name : file_list)
                if (!FileExists(file_name))
                    return false;

            return true;
        };

        /**
         *
         * check if file_name is a text file
         * @param StringView_t absolute path to target file
         * @returns bool true if file_name is a text file, false otherwise
         *
         */
        __0x_attr_FSC_itf inline static const bool IsTextFile(const StringView_t &file_name) noexcept
        {
            if (file_name.empty() || !FileExists(file_name))
                return false;

            return std::filesystem::is_regular_file(file_name.data());
        };

        /**
         *
         * check if file_name is a executable
         * @param StringView_t absolute path to target file
         * @returns bool true if file_name is executable, false otherwise
         *
         */
        __0x_attr_FSC_iex inline static const bool IsExecutable(const StringView_t &file_name) noexcept
        {
            if (IsTextFile(file_name.data()))
            {
                std::filesystem::perms f_perms = std::filesystem::status(file_name.data()).permissions();
                if (((f_perms & std::filesystem::perms::owner_exec) != std::filesystem::perms::none) || ((f_perms & std::filesystem::perms::group_exec) != std::filesystem::perms::none) ||
                    ((f_perms & std::filesystem::perms::others_exec) != std::filesystem::perms::none))
                    return true;
            }
            return false;
        };

        /**
         *
         * check if file_name is a symlink
         * @param StringView_t absolute path to target symlink
         * @returns bool true if file_name is symlink, false otherwise
         *
         */
        __0x_attr_FSC_isl inline static const bool IsSymlink(const StringView_t &file_name) noexcept
        {
            return std::filesystem::is_symlink(file_name.data());
        };

        /**
         *
         * check if file_name is a directory
         * @param StringView_t absolute path to target file
         * @returns bool true if file_name is directory, false otherwise
         *
         */
        __0x_attr_FSC_id inline static const bool IsDirectory(const StringView_t &file_name) noexcept
        {
            return std::filesystem::is_directory(file_name.data());
        };

        /**
         *
         * Read _file_name content and return full profiler structure associated with
         * _file_name.
         * @param StringView_t the absolute file path to read
         * @param bool a const boolean flag dictating if _file_name should be created on
         * missing or not
         * @returns stFileDescriptor a const read-only access to _file_name associated profile
         * structure
         *
         */
        __0x_attr_FSC_fr const struct stFileDescriptor FileRead(const StringView_t &_file_name, const bool _create_new = false)
        {

            this->__fileStreamStatusHandle(_file_name, _create_new);

            struct stFileDescriptor new_profiler(this->__createEmptyProfilerStructure(_file_name));

            int fileDescriptor(this->__openFileDescriptor(_file_name, eFileDescriptorMode::READ));

            struct stat file_stat_description(this->__createFileStat(fileDescriptor));

            if (file_stat_description.st_size > 0)
            {
                new_profiler.file_size = file_stat_description.st_size;

                fMap_t mapped_data_pointer(this->__createPointerMap(fileDescriptor, file_stat_description.st_size, true, 0));

                this->__verifyMemMapState(mapped_data_pointer);

                this->__allocMappedBytes(new_profiler.file_content, &mapped_data_pointer, file_stat_description.st_size);

                this->__descriptorMapClose(fileDescriptor, &mapped_data_pointer, file_stat_description.st_size);
            }
            return new_profiler;
        };

        /**
         *
         * put _buffer into file _fle_name, create new _file_name if _create_new is true and
         * _file_name is not found.
         * @param StringView_t read only argument value representing absolute path to
         * _file_name
         * @param StringView_t read only argument value holding data to be written into
         * _file_name
         * @param bool const boolean flag dictating if _file_name should be create if not
         * found
         * @returns void
         *
         */
        __0x_attr_FSC_fw inline void FileWrite(const StringView_t &_file_name, const StringView_t &_buffer, const bool _create_new = false)
        {

            this->__fileStreamStatusHandle(_file_name, _create_new, _buffer);

            int fileDescriptor(this->__openFileDescriptor(std::move(_file_name), eFileDescriptorMode::WRITE));

            const off_t file_size(_buffer.length());

            this->__descriptorResize(fileDescriptor, file_size);

            fMap_t mapped_data(this->__createPointerMap(fileDescriptor, file_size, false, 0));

            this->__verifyMemMapState(mapped_data);

            this->__copyMappedMemoryBytes(mapped_data, _buffer);

            this->__descriptorMapClose(fileDescriptor, &mapped_data, file_size);
        };

        /**
         *
         * Register new Profile, propagate _new_profile into local register.
         * @param struct stFileDescriptor new profile to allocate
         * @param bool if true, source will be moved into destination
         * @returns void
         *
         */
        __0x_attr_FSC_rnp inline void RegisterNewProfile(struct stFileDescriptor &_new_profile, const bool move_src = false) noexcept
        {
            if (_new_profile.file_size > 0) [[likely]]
            {
                std::lock_guard<std::mutex> _lock(this->_mtx_guard);
                this->_profile_stack_reg.createProfile(move_src ? std::move(_new_profile) : _new_profile);
                if (move_src)
                {
                    _new_profile = {};
                }
            }
        };

        /**
         *
         * Register new Profile(bulk mode), propagate _new_profile entries into local register.
         * @param std::unordered_map<struct stFileDescriptor> profile entries to allocate
         * @param bool if true, source will be moved into destination
         * @returns void
         *
         */
        __0x_attr_FSC_rnp inline void RegisterNewProfile(std::unordered_map<String_t, struct stFileDescriptor> &_new_profile, const bool move_src = false) noexcept
        {
            if (_new_profile.size() > 0) [[likely]]
            {
                std::lock_guard<std::mutex> _lock(this->_mtx_guard);
                for (const auto &[fk, descriptor] : _new_profile)
                {
                    if (descriptor.file_size <= 0)
                        continue;
                    this->_profile_stack_reg.createProfile(move_src ? std::move(descriptor) : descriptor);
                }
                if (move_src)
                {
                    for (auto &src : _new_profile)
                        src.second.Clean();
                    _new_profile.erase(_new_profile.begin(), _new_profile.end());
                }
            }
        };

        /**
         *
         * Register new Profile(bulk mode), propagate _new_profile entries into local register.
         * @param std::vector<struct stFileDescriptor> profile entries to allocate
         * @param bool if true, source will be moved into destination
         * @returns void
         *
         */
        __0x_attr_FSC_rnp inline void RegisterNewProfile(std::vector<struct stFileDescriptor> &_new_profile, const bool move_src) noexcept
        {
            if (_new_profile.size() > 0) [[likely]]
            {
                std::lock_guard<std::mutex> _lock(this->_mtx_guard);
                for (std::size_t profile_counter(0); profile_counter < _new_profile.size(); ++profile_counter)
                {
                    if (_new_profile[profile_counter].file_size <= 0)
                        continue;
                    this->_profile_stack_reg.createProfile(move_src ? std::move(_new_profile[profile_counter]) : _new_profile[profile_counter]);
                    if(move_src) _new_profile[profile_counter].Clean();
                }
                if (move_src)
                {
                    _new_profile.erase(_new_profile.begin(), _new_profile.end());
                }
            }
        };

        /**
         *
         * Get profiler register stack size
         * @returns std::size_t the size of register
         *
         */
        __0x_attr_FSC_gss constexpr std::size_t &GetRegisterSize(void) noexcept
        {
            std::lock_guard<std::mutex> _lock(this->_mtx_guard);
            return this->_profile_stack_reg.reg_stack_size;
        };

        /**
         *
         * Get Instance UID
         * @returns std::uint64_t the instance associated uid
         *
         */
        __0x_attr_FSC_gci constexpr std::uint64_t &GetFsControllerUID(void) noexcept
        {
            return this->_fs_instance_uid;
        };

        /**
         *
         * Get profiler structure data block at _profile_id index.
         * @param _ForeignKeyType_& reference to register profiler associated FK assigned at
         * allocation
         * @returns stFileDescriptor const struct description(profiler) identified by
         * _profile_id or empty descriptor if not found
         *
         */
        __0x_attr_FSC_gsp inline const struct stFileDescriptor GetProfile(const _ForeignKeyType_ &_profile_id) noexcept
        {
            std::lock_guard<std::mutex> _lock(this->_mtx_guard);
            return this->_profile_stack_reg.getProfile(_profile_id);
        };

        /**
         *
         * Get read-only internal stack register
         * @returns stProfilerStackRegister returns the internal register
         *
         */
        __0x_attr_FSC_gsptr inline const struct stProfilerStackRegister GetStackPointer(void) noexcept
        {
            std::lock_guard<std::mutex> _lock(this->_mtx_guard);
            return this->_profile_stack_reg;
        };

        /**
         *
         * delete a profile identified by _profile_id aka FK
         * @param _ForeignKeyType_& reference to register profiler associated FK
         * @param bool if true, will unlink globally, meaning the actual file will be removed
         * @returns void
         *
         */
        __0x_attr_FSC_dprf inline void DeleteProfile(const _ForeignKeyType_ &_profile_id) noexcept
        {
            std::lock_guard<std::mutex> _lock(this->_mtx_guard);
            this->_profile_stack_reg.eraseProfile(_profile_id);
        };

        /**
         *
         * Create _file_name.
         * @param StringView_t the absolute path to _file_name
         * @param StringView_t content to write into the file, defaults to nothing
         * @returns bool if created, true
         *
         */
        __0x_attr_FSC_cfl inline const bool CreateFile(const StringView_t &_file_name,

                                                                                                                                                       const StringView_t &_content = "")
        {
            std::ofstream fileCreate(_file_name.data());
            if (!fileCreate)
                throw std::runtime_error(std::move(String_t("File Create: ") + strerror(errno)));

            if (!_content.empty())
            {
                fileCreate.write(_content.data(), _content.length());
            }
            fileCreate.close();

            return FileExists(_file_name);
        };

        /**
         *
         * Create a directory.
         * @param StringView_t& directory path to create
         * @returns bool true if directory was created
         *
         */
        __0x_attr_FSC_cdir inline const bool CreateDirectory(const StringView_t &_directory) noexcept
        {
            std::filesystem::create_directories(_directory);
            return std::filesystem::is_directory(_directory);
        };

        /**
         *
         * Collect directory entries from _directory, if _recursive is true, it will traverse the entire
         * directories within _directory.
         * @param StringView_t& directory to collect from
         * @param bool optional! if true then recursive traversal
         * @returns std::vector<String_t> vector containing entries from _directory scan.
         *
         */
        __0x_attr_FSC_cdire const std::vector<String_t> CollectDirectoryEntries(const StringView_t &_directory,
                                                                                                                                                             const bool _recursive = false)
        {
            std::vector<String_t> vector_entries;
            if (_directory.empty())
                return {};
            if (_recursive)
            {
                for (const auto &d_entry : std::filesystem::recursive_directory_iterator(_directory))
                {
                    if (std::filesystem::is_regular_file(d_entry.path()))
                    {
                        vector_entries.push_back(d_entry.path().string());
                    }
                }
            }
            else
            {
                for (const auto &d_entry : std::filesystem::directory_iterator(_directory))
                {
                    if (std::filesystem::is_regular_file(d_entry.path()))
                    {
                        vector_entries.push_back(d_entry.path().string());
                    }
                }
            }
            return vector_entries;
        };

        /**
         *
         * Collect directory entries if any, constructs an object containing min/max collection entry
         * size, along with an std::array<string> register containing entry name(path) and a collection
         * array size.
         * @param StringView_t& directory to collect and profile
         * @param bool bit flag mandating recursive iteration or not
         * @param std::size_t threshold to use for register allocation, if register size do not exceed
         * or touch the threshold, structure will be deleted and empty block returned.
         * @returns stDirectoryCollectionStat a structure containing directory profiling information,
         * register stack, register size, min/max register entry size.
         *
         */
        inline const stDirectoryCollectionStat CollectDirectoryEntriesWithProfiling(const StringView_t &_directory, const bool _recursive, const std::size_t _threshold = 1)
        {
            stDirectoryCollectionStat new_collection_stat{.registry{this->CollectDirectoryEntries(_directory, _recursive)}};
            std::size_t max_size_get(0), min_size_get(0), largest_path_index(0), loop_counter(0);
            if (new_collection_stat.registry.size() > (std::size_t)0)
            {
                for (auto ncs_entry = new_collection_stat.registry.begin(); ncs_entry != new_collection_stat.registry.end(); ncs_entry++)
                {
                    ++loop_counter;
                    if (std::filesystem::file_size(*ncs_entry) > max_size_get)
                    {
                        max_size_get = std::filesystem::file_size(*ncs_entry);
                        largest_path_index = loop_counter - 1;
                    }
                    if (std::filesystem::file_size(*ncs_entry) < min_size_get)
                    {
                        min_size_get = std::filesystem::file_size(*ncs_entry);
                    }
                }
                new_collection_stat.min_size = min_size_get;
                new_collection_stat.max_size = max_size_get;
                new_collection_stat.registry_size = new_collection_stat.registry.size();
                new_collection_stat.largest_file_path = new_collection_stat.registry.at(largest_path_index);
            }
            if (new_collection_stat.registry_size < _threshold)
            {
                new_collection_stat = {};
            }
            return new_collection_stat;
        };

        /**
         *
         * Scan directory recursively, aggregate every entry which is a regular file type and return the
         * aggregation.
         * @param StringView_t& path to aggregate from
         * @returns directoryScanResult_t the aggregation
         *
         */
        __0x_attr_FSC_dirprf const directoryScanResult_t DirectoryProfiler(const StringView_t &path)
        {
            directoryScanResult_t scan_result;

            if (path.empty())
                return scan_result;
            if (path.length() < FS_MAX_FILE_NAME_LENGTH)
            {
                if (!std::filesystem::path(path).is_absolute())
                    throw std::runtime_error("Use an absolute path please!");
                this->__recursiveAggregation(path, scan_result);
            }
            return scan_result;
        };

        /**
         *
         * Delete a file_name, this action is not reversible.
         * @param StringView_t& path to file to remove
         * @returns void
         *
         */
        __0x_attr_FSC_delfl inline static void DeleteFile(const StringView_t &file_name)
        {
            if (file_name.empty())
                return;
            if (FileExists(file_name))
            {
                if (std::filesystem::is_regular_file(file_name))
                {
                    std::filesystem::remove(file_name);
                }
            }
        };

        /**
         *
         * Create a backup copy of dir_source directory as dir_dest, to override existing destination
         * files set dest_override to true, to copy empty files set copy_empty_files to true.
         * @param StringView_t& the source directory to copy
         * @param StringView_t dir_dest the destination backup directory
         * @param bool optional! it true will override existing files
         * @param bool optional! if true will copy empty files
         * @returns bool true if backup was successful
         *
         */
        __0x_attr_FSC_cdbk const bool CreateDirectoryBackup(const StringView_t &dir_source, const StringView_t &dir_dest, const bool create_backup_dir = false, const bool dest_override = false, const bool copy_empty_files = false)
        {
            try
            {
                const bool is_source(IsDirectory(dir_source)), is_destination(IsDirectory(dir_dest));

                if (!is_source)
                    throw std::runtime_error("source directory not valid for backup!");
                else if(!is_destination && create_backup_dir)    
                    std::filesystem::create_directories(dir_dest);
                
                if (IsDirectory(dir_dest))
                {
                    for (const auto &d_entry : std::filesystem::recursive_directory_iterator(dir_source))
                    {
                        const std::filesystem::path relative_source_path = std::filesystem::relative(d_entry.path(), dir_source);
                        const std::filesystem::path destinationPath = std::filesystem::path(dir_dest) / relative_source_path;

                        if (std::filesystem::is_directory(d_entry.status()))
                        {
                            if (!std::filesystem::exists(destinationPath))
                            {
                                std::filesystem::create_directories(destinationPath);
                            }
                        }
                        else
                        {
                            if (!copy_empty_files && std::filesystem::file_size(d_entry.path()) <= 0)
                                continue;
                            std::filesystem::copy_file(d_entry.path(), destinationPath, dest_override ? std::filesystem::copy_options::overwrite_existing : std::filesystem::copy_options::skip_existing);
                        }
                    }
                    this->sync_backup_exec_state = this->__directoryBackupVerify(dir_source, dir_dest);
                }
                else
                {
                    throw std::filesystem::filesystem_error::runtime_error("destination directory not created!");
                }
            }
            catch (const std::exception &e)
            {
                std::cerr << "Error: " << e.what() << "\n";
                this->sync_backup_exec_state = false;
            }
            return this->sync_backup_exec_state;
        };


        bool CreateDirectoryBackupJoinExecution(const StringView_t &dir_source, const StringView_t &dir_dest, const bool create_backup_dir = false, const bool dest_override = false, const bool copy_empty_files = false)
        {
            this->sync_backup_exec_state = false;
            std::thread sync_execute([&]{return this->CreateDirectoryBackup(dir_source, dir_dest, create_backup_dir, dest_override, copy_empty_files);});
            if(sync_execute.joinable()) sync_execute.join();
            return this->sync_backup_exec_state;
        };

        /**
         *
         * Check if directory contains a specific file type or file name.
         * @param StringView_t& the directory to scan
         * @param StringView_t& the file type or file name to lookup
         * @returns stDirectoryLookup structure containing scan variables
         *
         */
        template <typename _lookupReturnType, typename = std::enable_if_t<std::is_same_v<_lookupReturnType, stDirectoryLookup>>>
        __0x_attr_FSC_dcft inline const stDirectoryLookup DirectoryContainsFileType(
            const StringView_t &directory, const StringView_t &s_node, const bool recursive_scan = false)
        {
            std::cout << "Used stDirectoryLookup Type!\n";
            static_assert(std::is_same_v<_lookupReturnType, stDirectoryLookup>, "use stDirectoryLookup for _lookupReturnType");
            stDirectoryLookup lookup_table;

            if (directory.empty() || s_node.empty() || s_node.length() > FS_MAX_FILE_NAME_LENGTH || directory.size() > FS_MAX_FILE_NAME_LENGTH)
                return lookup_table;

            std::function<String_t(const StringView_t &path)> split_path = [&](const StringView_t &path)
            {
                return path.find("/") != std::string::npos ? static_cast<String_t>(path.substr(path.find_last_of("/") + 1).data()) : String_t("");
            };

            std::vector<String_t> dir_entries = this->CollectDirectoryEntries(directory, recursive_scan);

            if (dir_entries.size() > 0)
            {
                for (std::size_t j = 0; j < dir_entries.size(); ++j)
                {
                    lookup_table = {};
                    if (split_path(static_cast<StringView_t>(dir_entries[j])).find(s_node) != std::string::npos)
                    {
                        lookup_table.file = split_path(dir_entries[j]);
                        if (s_node.find(".") != std::string::npos && lookup_table.file.find(".") == std::string::npos)
                        {
                            lookup_table.file.clear();
                        }
                        lookup_table.path = lookup_table.file.empty() ? "" : dir_entries[j];
                        if ((lookup_table.has_found = !lookup_table.file.empty()) == true)
                            break;
                    }
                }
            }
            return lookup_table;
        };

        /**
         * 
         * Wipe Entire directory contents without possibility of reversing the action, remove contents and based on force_empty_folder also empty folders.
         * @param StringView_t& directory target
         * @param bool if force the deletion of empty folders...
         * @returns void
         * 
         */
        __0x_attr_FSC_dirwp inline void DirectoryWipe(const StringView_t &_directory, const bool force_empty_folder)
        {
            if (_directory.empty() || !IsDirectory(_directory))
                return;

            if (force_empty_folder)
            {
                std::filesystem::remove_all(_directory);
                return;
            }
            for (auto &block : std::filesystem::recursive_directory_iterator(_directory))
            {
                if (block.is_directory())
                {
                    DirectoryWipe((StringView_t)block.path().string(), force_empty_folder);
                }
                else
                {
                    std::filesystem::remove(block.path());
                }
            }
        };

        /**
         *
         * Calculate directory size, calculcating size of each entry recursivelly if found another
         * directory to scan, this can take longer depending on the target directory to scan, if
         * target to calculate size of is large, use GetDirectorySizeDetachHandler() which is a faster
         * version allocating detached thread execution handler to each sector depending on S(t).
         *
         * @param StringView_t& RO reference to directory target
         *  @returns std::size_t the calculated size
         *
         */
        inline std::size_t GetDirectorySize(const StringView_t &_directory)
        {
            if (_directory.empty())
                return 0;

            std::size_t t_size(0);

            if (IsDirectory(_directory))
            {
                for (const auto &d_entry : std::filesystem::recursive_directory_iterator(_directory))
                {
                    if (d_entry.is_regular_file())
                    {
                        t_size += d_entry.file_size();
                    }
                }
            }
            return t_size;
        };

        inline ~FSController() noexcept
        {
            if (this->_fs_new_instance) [[likely]]
                this->_fs_new_instance = false;
        };

    private:
        /**
         *
         * initialize object, either copy or move from _o depending on _tN value, template
         * requires _tN class type.
         * @param _tN the object to move/copy
         * @returns FSController the pointer to this object
         *
         */
        template <typename _tN, typename = std::enable_if<std::is_class_v<_tN>>>
        __0x_attr_FSC_ifc inline FSController *__initFsController(_tN _o) noexcept
        {
            if (*this != _o)
            {
                this->_profile_stack_reg = std::is_rvalue_reference_v<_tN> ? std::move(_o._profile_stack_reg) : _o._profile_stack_reg;
                this->_fs_new_instance = std::is_rvalue_reference_v<_tN> ? std::move(_o._fs_new_instance) : _o._fs_new_instance;
                this->_fs_instance_uid = std::is_rvalue_reference_v<_tN> ? std::move(_o._fs_instance_uid) : _o._fs_instance_uid;
            }
            return this;
        };

        /**
         *
         * Create a memory map for a file descriptor.
         *
         * @param int& fileDescriptor The file descriptor to map.
         * @param off_t& descriptor_size The size of the file descriptor.
         * @param bool read_mode Whether to open the map in read-only mode (default) or
         * read-write mode.
         * @param std::size_t offset_size The offset to the starting position of the map (default
         * is 0).
         *
         * @returns fMap_t The pointer to the mapped memory region.
         */
        __0x_attr_FSC_cpm inline fMap_t __createPointerMap(const int &fileDescriptor, const off_t &descriptor_size, const bool read_mode = true, const std::size_t &offset_size = 0) noexcept
        {
            const int proto_map_mode(read_mode ? PROT_READ : PROT_READ | PROT_WRITE);
            const int map_access_scope(read_mode ? MAP_PRIVATE : MAP_SHARED);
            const off_t map_offset = read_mode ? 0 : offset_size;
            return static_cast<fMap_t>(mmap(NULL, descriptor_size, proto_map_mode, map_access_scope, fileDescriptor, (read_mode ? map_offset : offset_size)));
        };

        /**
         *
         * Open a file descriptor for the given file name and mode.
         *
         * @param StringView_t _file_name The name of the file to open.
         * @param eFileDescriptorMode _mode The mode in which to open the file (read-only or
         * read-write).
         *
         * @returns int The file descriptor.
         *
         * @throws std::runtime_error If the file descriptor cannot be opened.
         */
        __0x_attr_FSC_ofd inline int __openFileDescriptor(const StringView_t &_file_name, const eFileDescriptorMode &_mode)
        {
            int descriptor_open(_mode == eFileDescriptorMode::READ ? open(_file_name.data(), O_RDONLY) : open(_file_name.data(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR));
            if (descriptor_open == -1) [[unlikely]]
                throw std::runtime_error(std::move(String_t("Cannot open file descriptor for file ") + _file_name.data()));
            return descriptor_open;
        };

        /**
         *
         * Create a file status structure for the given file descriptor.
         *
         * @param int& file_descriptor The file descriptor.
         *
         * @returns struct stat The file status structure.
         *
         * @throws std::runtime_error If the file status cannot be obtained.
         */
        __0x_attr_FSC_cfs inline struct stat __createFileStat(int &file_descriptor)
        {
            struct stat file_stat_description;
            if (fstat(file_descriptor, &file_stat_description) == -1) [[unlikely]]
                throw std::runtime_error(String_t("Error getting file stat") + strerror(errno));
            return file_stat_description;
        };

        /**
         *
         * Verify the state of a memory map.
         *
         * @param fMap_t& map_ptr The pointer to the mapped memory region.
         *
         * @throws std::runtime_error If the memory map is invalid.
         */
        __0x_attr_FSC_vms inline void __verifyMemMapState(const fMap_t &map_ptr)
        {
            if (map_ptr == MAP_FAILED) [[unlikely]]
                throw std::runtime_error(String_t("Error mapping file: ") + strerror(errno));
        };

        /**
         *
         * Allocate memory for a mapped region.
         *
         * @param String_t& destination_alloc The destination string.
         * @param fMap_t *__restrict__ mapped_data_pointer The pointer to the mapped memory
         * region.
         * @param off_t& map_size The size of the mapped region.
         *
         * @returns void
         */
        __0x_attr_FSC_amb inline void __allocMappedBytes(String_t &destination_alloc, const fMap_t *__restrict__ mapped_data_pointer, const off_t &map_size) noexcept
        {
            destination_alloc.assign(static_cast<fMap_t>(*mapped_data_pointer), map_size);
        };

        /**
         *
         * Close a file descriptor and unmap the associated memory region.
         *
         * @param int& fileDescriptor The file descriptor to close.
         * @param fMap_t *__restrict__ mapped_data_pointer The pointer to the mapped memory
         * region.
         * @param off_t& map_size The size of the mapped region.
         *
         * @throws std::runtime_error If the file descriptor cannot be closed or the memory
         * region cannot be unmapped.
         */
        __0x_attr_FSC_dmc inline void __descriptorMapClose(int &fileDescriptor, const fMap_t *__restrict__ mapped_data_pointer, const off_t &map_size)
        {
            if (munmap(*mapped_data_pointer, map_size) == -1) [[unlikely]]
                throw std::runtime_error(String_t("Cannot unmap address! ") + strerror(errno));
            close(fileDescriptor);
        };

        /**
         *
         * Resize a file descriptor.
         *
         * @param int& descriptor The file descriptor to resize.
         * @param off_t& offset_size The new size of the file descriptor.
         *
         * @throws std::runtime_error If the file descriptor cannot be resized.
         */
        __0x_attr_FSC_drz inline void __descriptorResize(int &descriptor, const off_t &offset_size)
        {
            if (ftruncate(descriptor, offset_size) == -1) [[unlikely]]
                throw std::runtime_error(String_t("Cannot resize descriptor!") + strerror(errno));
        };

        /**
         *
         * Create an empty profiler structure.
         *
         * @param StringView_t _file_name The name of the file (optional).
         *
         * @returns struct stFileDescriptor The empty profiler structure.
         */
        __0x_attr_FSC_cps constexpr struct stFileDescriptor __createEmptyProfilerStructure(const StringView_t _file_name = "") noexcept
        {
            return stFileDescriptor{.file_content{""}, .file_name{static_cast<String_t>(_file_name)}, .file_size{0}};
        };

        /**
         *
         * Copy data from a mapped memory region to a destination string.
         *
         * @param fMap_t& from_map The pointer to the mapped memory region.
         * @param StringView_t destination The destination string.
         *
         * @returns void
         */
        __0x_attr_FSC_cmb inline void __copyMappedMemoryBytes(const fMap_t &destination, const StringView_t &source) noexcept
        {
            memcpy(destination, source.data(), source.length());
        };

        /**
         *
         * Handle file streaming operations, handles _create_new value, if true, this will create an
         * empty or not-empty file based on _buffer value.
         * @param StringView_t the file name
         * @param bool if create new file or not
         * @param StringView_t the buffer to write into _file_name
         * @returns void
         *
         */
        __0x_attr_FSC_fssh inline void __fileStreamStatusHandle(const StringView_t &_file_name, const bool _create_new,
                                                                                                                                         const StringView_t &_buffer = "")
        {
            if (!FileExists(_file_name))
            {
                if (_create_new)
                {
                    if (!this->CreateFile(_file_name, _buffer))
                    {
                        throw std::runtime_error(std::move(String_t("Cannot Create File ") + _file_name.data()));
                    }
                }
                else
                {
                    throw std::runtime_error(std::move(String_t("File do not exist: ") + _file_name.data()));
                }
            }
        };

        /**
         *
         * Recursive directory aggregation, aggregate entries into recursive_scan.
         * @param StringView_t the path for directory
         * @param directoryScanResult_t the aggregation block for new entries to use
         * @returns void
         *
         */
        __0x_attr_FSC_recaggr inline void __recursiveAggregation(
            const StringView_t &_p, directoryScanResult_t &recursive_scan) noexcept {
            if (IsDirectory(_p))
            {
                std::filesystem::directory_iterator rdi(_p);
                for (auto &dir_entry : rdi)
                {
                    if (dir_entry.is_directory())
                    {
                        __recursiveAggregation(static_cast<StringView_t>(dir_entry.path().string()), recursive_scan);
                    }
                    else
                    {
                        struct stFileDescriptor new_description = this->FileRead(dir_entry.path().string(), false);
                        if (new_description.file_size > 0)
                        {
                            recursive_scan.insert_or_assign(static_cast<_ForeignKeyType_>(new_description.file_name), std::move(new_description));
                        }
                    }
                }
            }
        };

        /**
         * 
         * Verify if directories(source, backup) are the same by checking they're size...
         * @param StringView_t& source
         * @param StringView_t& destination
         * @returns bool true if same
         * 
         */
        __0x_attr_FSC_dirbkv const bool __directoryBackupVerify(const StringView_t& source, const StringView_t& destination) {
            return this->GetDirectorySize(source) == this->GetDirectorySize(destination);
        };
    };

#endif

}; // namespace FSControllerModule

typedef FSControllerModule::FSController<> _FSC_;

#endif
